//! Authentication of Weft internal services (host agents and the egress
//! gateway) to the control plane with AWS IAM, in the style of Vault's AWS
//! IAM auth method.
//!
//! The caller signs, but does not send, an STS `GetCallerIdentity` request
//! and passes it to the control plane in the `X-Weft-Internal-Auth` header.
//! The control plane replays it to STS, which answers with the ARN of the
//! caller's IAM role; the control plane maps that role to a host or to the
//! gateway. The signed `x-weft-server-id` header binds the request to one
//! server, so the control plane must require it in `SignedHeaders` and check
//! that it names the server making the call. STS rejects signatures older
//! than 15 minutes, which bounds how long a captured header can be replayed.
//!
//! In development the header is a shared token instead: `dev-token <token>`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context};
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Header that carries the credential on every internal control-plane call.
pub const AUTH_HEADER: &str = "x-weft-internal-auth";
/// Signed header naming the server the request authenticates.
pub const SERVER_ID_HEADER: &str = "x-weft-server-id";
/// The exact STS request body the control plane accepts.
pub const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
pub const STS_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";
/// How long a signed header is reused. STS accepts it for 15 minutes; the
/// margin covers clock skew and the time the control plane takes to replay.
pub const DEFAULT_HEADER_TTL: Duration = Duration::from_secs(5 * 60);

const MAX_SERVER_ID_LEN: usize = 128;

/// A signed STS `GetCallerIdentity` request, as the control plane receives it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStsRequest {
    pub method: String,
    pub url: String,
    /// Lowercase header name to value.
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl SignedStsRequest {
    /// The `X-Weft-Internal-Auth` header value: `aws-iam <base64 JSON>`.
    pub fn to_header_value(&self) -> String {
        let json = serde_json::to_vec(self).expect("string maps always serialize");
        format!("aws-iam {}", BASE64.encode(json))
    }

    /// Parses a header value produced by [`Self::to_header_value`].
    pub fn from_header_value(value: &str) -> anyhow::Result<Self> {
        let encoded = value
            .strip_prefix("aws-iam ")
            .ok_or_else(|| anyhow!("not an aws-iam credential"))?;
        let json = BASE64.decode(encoded.trim()).context("invalid base64")?;
        serde_json::from_slice(&json).context("invalid signed request JSON")
    }
}

impl fmt::Debug for SignedStsRequest {
    // The signature and session token are a bearer credential for 15 minutes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: BTreeMap<&str, &str> = self
            .headers
            .iter()
            .map(|(k, v)| {
                let v = match k.as_str() {
                    "authorization" | "x-amz-security-token" => "<redacted>",
                    _ => v.as_str(),
                };
                (k.as_str(), v)
            })
            .collect();
        f.debug_struct("SignedStsRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body", &self.body)
            .finish()
    }
}

/// Signs the STS request with explicit credentials at a fixed time. Pure, so
/// it can be tested deterministically.
pub fn sign_sts_request(
    region: &str,
    server_id: &str,
    credentials: &Credentials,
    time: SystemTime,
) -> anyhow::Result<SignedStsRequest> {
    validate_region(region)?;
    validate_server_id(server_id)?;
    let host = format!("sts.{region}.amazonaws.com");
    let url = format!("https://{host}/");
    let mut headers = BTreeMap::from([
        ("host".to_owned(), host),
        ("content-type".to_owned(), STS_CONTENT_TYPE.to_owned()),
        (SERVER_ID_HEADER.to_owned(), server_id.to_owned()),
    ]);

    let identity = credentials.clone().into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("sts")
        .time(time)
        .settings(SigningSettings::default())
        .build()
        .context("building SigV4 parameters")?
        .into();
    let signable = SignableRequest::new(
        "POST",
        &url,
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(STS_BODY.as_bytes()),
    )
    .context("building signable request")?;
    let (instructions, _signature) = sign(signable, &params)
        .context("signing STS request")?
        .into_parts();
    for (name, value) in instructions.headers() {
        headers.insert(name.to_ascii_lowercase(), value.to_owned());
    }
    let signed_headers = headers
        .get("authorization")
        .and_then(|auth| auth.split("SignedHeaders=").nth(1))
        .and_then(|rest| rest.split(',').next())
        .unwrap_or_default();
    if !signed_headers.split(';').any(|h| h == SERVER_ID_HEADER) {
        bail!("signer dropped {SERVER_ID_HEADER} from SignedHeaders");
    }

    Ok(SignedStsRequest {
        method: "POST".to_owned(),
        url,
        headers,
        body: STS_BODY.to_owned(),
    })
}

/// Builds an `aws-iam` header with credentials from the default AWS chain
/// (environment, ECS container credentials on Fargate, IMDSv2 on EC2).
///
/// Loads the chain on every call; long-running callers should keep an
/// [`AwsIamSigner`] in a [`HeaderCache`] instead.
pub async fn aws_iam_header(region: &str, server_id: &str) -> anyhow::Result<String> {
    AwsIamSigner::from_default_chain(region, server_id)
        .await?
        .sign()
        .await
        .map(|(header, _)| header)
}

/// The development credential. Accepted only by a control plane running in
/// development mode.
pub fn dev_token_header(token: &str) -> String {
    format!("dev-token {token}")
}

/// Signs STS requests with credentials from a provider.
#[derive(Clone)]
pub struct AwsIamSigner {
    region: String,
    server_id: String,
    provider: SharedCredentialsProvider,
}

impl fmt::Debug for AwsIamSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsIamSigner")
            .field("region", &self.region)
            .field("server_id", &self.server_id)
            .finish_non_exhaustive()
    }
}

impl AwsIamSigner {
    /// Uses the default AWS credential chain.
    pub async fn from_default_chain(region: &str, server_id: &str) -> anyhow::Result<Self> {
        validate_region(region)?;
        validate_server_id(server_id)?;
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .load()
            .await;
        let provider = config
            .credentials_provider()
            .ok_or_else(|| anyhow!("no AWS credentials provider is configured"))?;
        Ok(Self {
            region: region.to_owned(),
            server_id: server_id.to_owned(),
            provider,
        })
    }

    pub fn with_provider(
        region: &str,
        server_id: &str,
        provider: impl ProvideCredentials + 'static,
    ) -> anyhow::Result<Self> {
        validate_region(region)?;
        validate_server_id(server_id)?;
        Ok(Self {
            region: region.to_owned(),
            server_id: server_id.to_owned(),
            provider: SharedCredentialsProvider::new(provider),
        })
    }

    /// Returns the header and when the credentials behind it expire, if they do.
    pub async fn sign(&self) -> anyhow::Result<(String, Option<SystemTime>)> {
        let credentials = self
            .provider
            .provide_credentials()
            .await
            .context("loading AWS credentials")?;
        let signed = sign_sts_request(
            &self.region,
            &self.server_id,
            &credentials,
            SystemTime::now(),
        )?;
        Ok((signed.to_header_value(), credentials.expiry()))
    }
}

/// Where internal-auth headers come from.
#[derive(Clone)]
pub enum InternalAuth {
    AwsIam(AwsIamSigner),
    DevToken(String),
}

impl fmt::Debug for InternalAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsIam(signer) => f.debug_tuple("AwsIam").field(signer).finish(),
            Self::DevToken(_) => f.write_str("DevToken(<redacted>)"),
        }
    }
}

/// Reuses a signed header for a few minutes so that not every control-plane
/// call signs a new request. Concurrent callers share one signing operation.
#[derive(Debug)]
pub struct HeaderCache {
    auth: InternalAuth,
    ttl: Duration,
    cached: tokio::sync::Mutex<Option<(Instant, Arc<str>)>>,
}

impl HeaderCache {
    pub fn new(auth: InternalAuth) -> Self {
        Self::with_ttl(auth, DEFAULT_HEADER_TTL)
    }

    pub fn with_ttl(auth: InternalAuth, ttl: Duration) -> Self {
        Self {
            auth,
            ttl,
            cached: tokio::sync::Mutex::new(None),
        }
    }

    /// The current header value, signing a new one when the cached one is stale.
    pub async fn header(&self) -> anyhow::Result<Arc<str>> {
        let signer = match &self.auth {
            InternalAuth::DevToken(token) => return Ok(dev_token_header(token).into()),
            InternalAuth::AwsIam(signer) => signer,
        };
        let mut cached = self.cached.lock().await;
        if let Some((expires, value)) = cached.as_ref() {
            if Instant::now() < *expires {
                return Ok(value.clone());
            }
        }
        let (header, credentials_expiry) = signer.sign().await?;
        let header: Arc<str> = header.into();
        *cached = Some((
            Instant::now() + self.reuse_for(credentials_expiry),
            header.clone(),
        ));
        Ok(header)
    }

    /// Drops the cached header, e.g. after the control plane rejected it.
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }

    /// A header must not outlive the session credentials that signed it.
    fn reuse_for(&self, credentials_expiry: Option<SystemTime>) -> Duration {
        let Some(expiry) = credentials_expiry else {
            return self.ttl;
        };
        let remaining = expiry
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .saturating_sub(Duration::from_secs(60));
        remaining.min(self.ttl)
    }
}

fn validate_region(region: &str) -> anyhow::Result<()> {
    let ok = !region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !ok {
        bail!("invalid AWS region {region:?}");
    }
    Ok(())
}

fn validate_server_id(server_id: &str) -> anyhow::Result<()> {
    let ok = !server_id.is_empty()
        && server_id.len() <= MAX_SERVER_ID_LEN
        && server_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b));
    if !ok {
        bail!("invalid server ID {server_id:?}: use up to {MAX_SERVER_ID_LEN} characters from [A-Za-z0-9-_.:]");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // AWS documentation example keys; not real credentials.
    const ACCESS_KEY: &str = "AKIDEXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn fixed_time() -> SystemTime {
        // 2026-01-02T03:04:05Z
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_323_045)
    }

    fn creds(token: Option<&str>) -> Credentials {
        Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            token.map(str::to_owned),
            None,
            "test",
        )
    }

    #[test]
    fn signs_exact_request_with_server_id_in_signed_headers() {
        let signed = sign_sts_request(
            "eu-west-1",
            "host-01",
            &creds(Some("session-token")),
            fixed_time(),
        )
        .unwrap();
        assert_eq!(signed.method, "POST");
        assert_eq!(signed.url, "https://sts.eu-west-1.amazonaws.com/");
        assert_eq!(signed.body, "Action=GetCallerIdentity&Version=2011-06-15");
        let h = &signed.headers;
        assert_eq!(h["host"], "sts.eu-west-1.amazonaws.com");
        assert_eq!(h["content-type"], STS_CONTENT_TYPE);
        assert_eq!(h["x-weft-server-id"], "host-01");
        assert_eq!(h["x-amz-date"], "20260102T030405Z");
        assert_eq!(h["x-amz-security-token"], "session-token");
        assert!(h.keys().all(|k| k.chars().all(|c| !c.is_ascii_uppercase())));
        let auth = &h["authorization"];
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/eu-west-1/sts/aws4_request, "
        ));
        assert!(
            auth.contains(
                "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-weft-server-id,"
            ),
            "{auth}"
        );
    }

    #[test]
    fn signature_matches_an_independent_sigv4_computation() {
        let signed = sign_sts_request("us-east-1", "gw-1", &creds(None), fixed_time()).unwrap();
        let canonical = format!(
            "POST\n/\n\n\
             content-type:{STS_CONTENT_TYPE}\n\
             host:sts.us-east-1.amazonaws.com\n\
             x-amz-date:20260102T030405Z\n\
             x-weft-server-id:gw-1\n\n\
             content-type;host;x-amz-date;x-weft-server-id\n{}",
            hex::encode(Sha256::digest(STS_BODY))
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n20260102T030405Z\n20260102/us-east-1/sts/aws4_request\n{}",
            hex::encode(Sha256::digest(canonical))
        );
        let key = v4::generate_signing_key(SECRET_KEY, fixed_time(), "us-east-1", "sts");
        let expected = v4::calculate_signature(key, string_to_sign.as_bytes());
        let auth = &signed.headers["authorization"];
        assert!(auth.ends_with(&format!("Signature={expected}")), "{auth}");
        assert!(!signed.headers.contains_key("x-amz-security-token"));
    }

    #[test]
    fn header_value_round_trips_and_debug_redacts() {
        let signed =
            sign_sts_request("us-east-1", "gw-1", &creds(Some("tok")), fixed_time()).unwrap();
        let value = signed.to_header_value();
        assert!(value.starts_with("aws-iam "));
        assert_eq!(SignedStsRequest::from_header_value(&value).unwrap(), signed);
        let debug = format!("{signed:?}");
        assert!(!debug.contains("Signature="));
        assert!(!debug.contains("tok\""));
        assert_eq!(dev_token_header("abc"), "dev-token abc");
    }

    #[test]
    fn rejects_bad_region_and_server_id() {
        let c = creds(None);
        assert!(sign_sts_request("evil.com/x", "a", &c, fixed_time()).is_err());
        assert!(sign_sts_request("us-east-1", "", &c, fixed_time()).is_err());
        assert!(sign_sts_request("us-east-1", "a\r\nb", &c, fixed_time()).is_err());
        assert!(sign_sts_request("us-east-1", &"a".repeat(129), &c, fixed_time()).is_err());
    }

    #[tokio::test]
    async fn header_cache_reuses_until_ttl_and_respects_credential_expiry() {
        let signer = AwsIamSigner::with_provider("us-east-1", "gw-1", creds(None)).unwrap();
        let cache = HeaderCache::with_ttl(InternalAuth::AwsIam(signer), Duration::from_secs(300));
        let a = cache.header().await.unwrap();
        let b = cache.header().await.unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "second call must reuse the cached header"
        );
        cache.invalidate().await;
        let c = cache.header().await.unwrap();
        assert!(!Arc::ptr_eq(&a, &c));

        let expiring = Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            Some("t".into()),
            Some(SystemTime::now() + Duration::from_secs(30)),
            "test",
        );
        let signer = AwsIamSigner::with_provider("us-east-1", "gw-1", expiring).unwrap();
        let cache = HeaderCache::new(InternalAuth::AwsIam(signer));
        let a = cache.header().await.unwrap();
        let b = cache.header().await.unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "credentials about to expire must not be reused"
        );

        let dev = HeaderCache::new(InternalAuth::DevToken("t0k".into()));
        assert_eq!(&*dev.header().await.unwrap(), "dev-token t0k");
        assert!(!format!("{dev:?}").contains("t0k"));
    }
}
