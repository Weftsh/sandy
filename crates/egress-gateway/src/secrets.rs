//! Credential secrets for the credential proxy.
//!
//! Secrets come from AWS Secrets Manager in production and from a static map
//! in development and tests, behind [`SecretSource`]. Values are cached for a
//! few minutes so a busy sandbox does not call Secrets Manager per request,
//! and they are wrapped in [`SecretValue`], whose `Debug` never prints them.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use http::HeaderValue;
use weft_netpolicy::CredentialRule;

use crate::cache::TtlCache;

pub const SECRET_TTL: Duration = Duration::from_secs(5 * 60);
const SECRET_CACHE_ENTRIES: usize = 1024;

/// A secret string. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Arc<str>);

impl SecretValue {
    pub fn new(value: impl Into<Arc<str>>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// Error messages name secrets and keys but never contain their values.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    #[error("secret {0:?} not found")]
    NotFound(String),
    #[error("fetching secret {id:?} failed: {message}")]
    Fetch { id: String, message: String },
    #[error("secret {0:?} has no string value")]
    NoString(String),
    #[error("secret is not a JSON object, but the rule names secretKey {0:?}")]
    NotJsonObject(String),
    #[error("secret has no string field {0:?}")]
    MissingKey(String),
    #[error("secret value cannot be sent in an HTTP header")]
    InvalidHeaderValue,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where secret strings come from.
pub trait SecretSource: Send + Sync {
    fn fetch<'a>(&'a self, secret_id: &'a str) -> BoxFuture<'a, Result<SecretValue, SecretError>>;
}

/// AWS Secrets Manager `GetSecretValue`, with the default credential chain.
pub struct AwsSecretsManager {
    client: aws_sdk_secretsmanager::Client,
}

impl AwsSecretsManager {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: aws_sdk_secretsmanager::Client::new(config),
        }
    }
}

impl SecretSource for AwsSecretsManager {
    fn fetch<'a>(&'a self, secret_id: &'a str) -> BoxFuture<'a, Result<SecretValue, SecretError>> {
        Box::pin(async move {
            let out = self
                .client
                .get_secret_value()
                .secret_id(secret_id)
                .send()
                .await
                .map_err(|e| {
                    let service_error = e.as_service_error();
                    if service_error.is_some_and(|s| s.is_resource_not_found_exception()) {
                        return SecretError::NotFound(secret_id.to_owned());
                    }
                    SecretError::Fetch {
                        id: secret_id.to_owned(),
                        message: aws_sdk_secretsmanager::error::DisplayErrorContext(&e).to_string(),
                    }
                })?;
            if let Some(s) = out.secret_string() {
                return Ok(SecretValue::new(s));
            }
            out.secret_binary()
                .and_then(|b| std::str::from_utf8(b.as_ref()).ok())
                .map(SecretValue::new)
                .ok_or_else(|| SecretError::NoString(secret_id.to_owned()))
        })
    }
}

/// A fixed map of secret ID to value, for development and tests.
pub struct StaticSecrets {
    values: HashMap<String, SecretValue>,
}

impl StaticSecrets {
    pub fn new(values: HashMap<String, String>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|(k, v)| (k, SecretValue::new(v)))
                .collect(),
        }
    }

    /// Reads a JSON object mapping secret IDs to secret strings.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let values: HashMap<String, String> = serde_json::from_str(&text)
            .with_context(|| format!("{} must be a JSON object of strings", path.display()))?;
        Ok(Self::new(values))
    }
}

impl SecretSource for StaticSecrets {
    fn fetch<'a>(&'a self, secret_id: &'a str) -> BoxFuture<'a, Result<SecretValue, SecretError>> {
        let result = self
            .values
            .get(secret_id)
            .cloned()
            .ok_or_else(|| SecretError::NotFound(secret_id.to_owned()));
        Box::pin(async move { result })
    }
}

/// Cached access to secrets, and rendering of credential headers.
pub struct SecretStore {
    source: Arc<dyn SecretSource>,
    cache: TtlCache<String, SecretValue>,
    ttl: Duration,
}

impl SecretStore {
    pub fn new(source: Arc<dyn SecretSource>) -> Self {
        Self {
            source,
            cache: TtlCache::new(SECRET_CACHE_ENTRIES),
            ttl: SECRET_TTL,
        }
    }

    pub async fn get(&self, secret_id: &str) -> Result<SecretValue, SecretError> {
        let key = secret_id.to_owned();
        if let Some(v) = self.cache.get(&key) {
            return Ok(v);
        }
        let value = self.source.fetch(secret_id).await?;
        self.cache.insert(key, value.clone(), self.ttl);
        Ok(value)
    }

    /// The header value to inject for `rule`, marked sensitive.
    pub async fn header_value(&self, rule: &CredentialRule) -> Result<HeaderValue, SecretError> {
        let raw = self.get(&rule.secret_id).await?;
        let secret = extract_secret(&raw, rule.secret_key.as_deref())?;
        let mut value = HeaderValue::from_str(&rule.render(secret.expose()))
            .map_err(|_| SecretError::InvalidHeaderValue)?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// Picks the value to inject: the whole secret string, or, when the rule
/// names a key, that string field of the secret's JSON object.
pub fn extract_secret(raw: &SecretValue, key: Option<&str>) -> Result<SecretValue, SecretError> {
    let Some(key) = key else {
        return Ok(raw.clone());
    };
    let object: serde_json::Map<String, serde_json::Value> = serde_json::from_str(raw.expose())
        .map_err(|_| SecretError::NotJsonObject(key.to_owned()))?;
    match object.get(key) {
        Some(serde_json::Value::String(s)) => Ok(SecretValue::new(s.as_str())),
        _ => Err(SecretError::MissingKey(key.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(key: Option<&str>, format: Option<&str>) -> CredentialRule {
        CredentialRule {
            host: "api.example.com".into(),
            header: "authorization".into(),
            secret_id: "s1".into(),
            secret_key: key.map(Into::into),
            format: format.map(Into::into),
        }
    }

    #[test]
    fn extracts_whole_string_or_json_key() {
        let raw = SecretValue::new(r#"{"apiKey":"sk-123","n":5}"#);
        assert_eq!(extract_secret(&raw, None).unwrap(), raw);
        assert_eq!(
            extract_secret(&raw, Some("apiKey")).unwrap().expose(),
            "sk-123"
        );
        assert_eq!(
            extract_secret(&raw, Some("missing")),
            Err(SecretError::MissingKey("missing".into()))
        );
        assert_eq!(
            extract_secret(&raw, Some("n")),
            Err(SecretError::MissingKey("n".into())),
            "only string fields are credentials"
        );
        let plain = SecretValue::new("sk-plain");
        assert_eq!(
            extract_secret(&plain, Some("apiKey")),
            Err(SecretError::NotJsonObject("apiKey".into()))
        );
        let array = SecretValue::new(r#"["sk"]"#);
        assert!(extract_secret(&array, Some("0")).is_err());
    }

    #[test]
    fn debug_and_errors_never_show_values() {
        let v = SecretValue::new("sk-very-secret");
        assert!(!format!("{v:?}").contains("sk-very-secret"));
        let e = extract_secret(&SecretValue::new("sk-very-secret"), Some("k")).unwrap_err();
        assert!(!e.to_string().contains("sk-very-secret"));
    }

    #[tokio::test]
    async fn renders_sensitive_header_values_and_caches() {
        struct Counting(std::sync::atomic::AtomicUsize);
        impl SecretSource for Counting {
            fn fetch<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<SecretValue, SecretError>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async { Ok(SecretValue::new(r#"{"k":"abc"}"#)) })
            }
        }
        let source = Arc::new(Counting(0.into()));
        let store = SecretStore::new(source.clone());
        let v = store
            .header_value(&rule(Some("k"), Some("Bearer {{secret}}")))
            .await
            .unwrap();
        assert_eq!(v, "Bearer abc");
        assert!(v.is_sensitive());
        store.header_value(&rule(Some("k"), None)).await.unwrap();
        assert_eq!(source.0.load(std::sync::atomic::Ordering::SeqCst), 1);

        let bad = StaticSecrets::new(HashMap::from([("s1".to_owned(), "a\r\nb".to_owned())]));
        let store = SecretStore::new(Arc::new(bad));
        assert_eq!(
            store.header_value(&rule(None, None)).await,
            Err(SecretError::InvalidHeaderValue)
        );
        assert!(matches!(
            SecretStore::new(Arc::new(StaticSecrets::new(HashMap::new())))
                .get("nope")
                .await,
            Err(SecretError::NotFound(_))
        ));
    }
}
