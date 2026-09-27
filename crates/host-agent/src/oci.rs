//! Minimal OCI distribution client: resolves an image reference, picks the
//! linux/amd64 manifest, and downloads verified layer blobs.
//!
//! Supports anonymous and bearer-token registries (Docker Hub, GHCR) and
//! Basic auth registries (Amazon ECR with credentials from
//! GetAuthorizationToken, passed in by the control plane).

use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// Largest manifest or config document accepted.
const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OciError {
    #[error("invalid image reference {0:?}")]
    BadReference(String),
    #[error("registry request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("registry returned HTTP {status} for {what}")]
    Status { status: u16, what: String },
    #[error("registry authentication failed: {0}")]
    Auth(String),
    #[error("image has no linux/{0} manifest")]
    NoPlatform(String),
    #[error("digest mismatch for {digest}: got {actual}")]
    DigestMismatch { digest: String, actual: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad document: {0}")]
    Json(#[from] serde_json::Error),
}

/// A parsed `registry/repository[:tag][@digest]` reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host, e.g. `registry-1.docker.io` or `1234.dkr.ecr.us-east-1.amazonaws.com`.
    pub registry: String,
    pub repository: String,
    /// Tag or digest to fetch.
    pub reference: String,
}

impl ImageRef {
    pub fn parse(input: &str) -> Result<Self, OciError> {
        let bad = || OciError::BadReference(input.to_owned());
        let s = input.trim();
        if s.is_empty() || s.len() > 512 || s.contains("://") || s.chars().any(char::is_whitespace) {
            return Err(bad());
        }
        let (name, digest) = match s.split_once('@') {
            Some((n, d)) => {
                let valid = d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
                if !valid {
                    return Err(bad());
                }
                (n, Some(d.to_owned()))
            }
            None => (s, None),
        };
        let (registry, rest) = match name.split_once('/') {
            Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
                (first.to_owned(), rest.to_owned())
            }
            _ => ("docker.io".to_owned(), name.to_owned()),
        };
        let (repository, tag) = match rest.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_owned(), t.to_owned()),
            _ => (rest, "latest".to_owned()),
        };
        let repository = if registry == "docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        let valid_repo = repository.split('/').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        });
        let valid_tag = !tag.is_empty() && tag.len() <= 128 && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !valid_repo || !valid_tag {
            return Err(bad());
        }
        let registry = if registry == "docker.io" { "registry-1.docker.io".to_owned() } else { registry };
        Ok(Self { registry, repository, reference: digest.unwrap_or(tag) })
    }
}

/// Image configuration fields the template builder uses.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ImageConfig {
    #[serde(default, rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    config: Option<ImageConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: Option<String>,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    media_type: Option<String>,
    #[serde(default)]
    manifests: Option<Vec<Descriptor>>,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Option<Vec<Descriptor>>,
}

/// A downloaded, digest-verified layer.
#[derive(Clone, Debug)]
pub struct Layer {
    pub path: PathBuf,
    pub media_type: String,
}

pub struct PulledImage {
    pub config: ImageConfig,
    pub layers: Vec<Layer>,
}

#[derive(Clone, Debug, Default)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct Puller {
    http: reqwest::Client,
    creds: Credentials,
    token: Option<String>,
    arch: &'static str,
}

impl Puller {
    pub fn new(creds: Credentials) -> Result<Self, OciError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("weft-host-agent/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self { http, creds, token: None, arch: "amd64" })
    }

    /// Resolves the image and downloads its layers into `dir`.
    pub async fn pull(&mut self, image: &ImageRef, dir: &Path) -> Result<PulledImage, OciError> {
        tokio::fs::create_dir_all(dir).await?;
        let mut manifest = self.manifest(image, &image.reference).await?;
        if let Some(list) = manifest.manifests.take() {
            let chosen = list
                .iter()
                .find(|d| d.platform.as_ref().is_some_and(|p| p.os == "linux" && p.architecture == self.arch))
                .ok_or_else(|| OciError::NoPlatform(self.arch.to_owned()))?;
            let digest = chosen.digest.clone();
            manifest = self.manifest(image, &digest).await?;
        }
        let config_desc = manifest.config.ok_or_else(|| OciError::Unsupported("manifest has no config".into()))?;
        let config_bytes = self.blob_bytes(image, &config_desc).await?;
        let config = serde_json::from_slice::<ConfigFile>(&config_bytes)?.config.unwrap_or_default();

        let mut layers = Vec::new();
        for (i, desc) in manifest.layers.unwrap_or_default().iter().enumerate() {
            let media_type = desc.media_type.clone().unwrap_or_default();
            if !is_supported_layer(&media_type) {
                return Err(OciError::Unsupported(format!("layer media type {media_type:?}")));
            }
            let path = dir.join(format!("layer-{i:03}"));
            self.download_blob(image, desc, &path).await?;
            layers.push(Layer { path, media_type });
        }
        Ok(PulledImage { config, layers })
    }

    async fn manifest(&mut self, image: &ImageRef, reference: &str) -> Result<Manifest, OciError> {
        let url = format!("https://{}/v2/{}/manifests/{}", image.registry, image.repository, reference);
        let resp = self.get(image, &url, Some(ACCEPT_MANIFESTS)).await?;
        let bytes = read_limited(resp, MAX_DOCUMENT_BYTES).await?;
        if reference.starts_with("sha256:") {
            verify_digest(reference, &bytes)?;
        }
        let m: Manifest = serde_json::from_slice(&bytes)?;
        if m.media_type.as_deref().is_some_and(|t| t.contains("manifest.v1+prettyjws")) {
            return Err(OciError::Unsupported("schema 1 manifests".into()));
        }
        Ok(m)
    }

    async fn blob_bytes(&mut self, image: &ImageRef, desc: &Descriptor) -> Result<Vec<u8>, OciError> {
        if desc.size as usize > MAX_DOCUMENT_BYTES {
            return Err(OciError::Unsupported("config blob too large".into()));
        }
        let url = format!("https://{}/v2/{}/blobs/{}", image.registry, image.repository, desc.digest);
        let resp = self.get(image, &url, None).await?;
        let bytes = read_limited(resp, MAX_DOCUMENT_BYTES).await?;
        verify_digest(&desc.digest, &bytes)?;
        Ok(bytes)
    }

    async fn download_blob(&mut self, image: &ImageRef, desc: &Descriptor, path: &Path) -> Result<(), OciError> {
        let url = format!("https://{}/v2/{}/blobs/{}", image.registry, image.repository, desc.digest);
        let resp = self.get(image, &url, None).await?;
        let mut file = tokio::fs::File::create(path).await?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            written += chunk.len() as u64;
            if written > desc.size {
                return Err(OciError::Unsupported(format!("blob {} is larger than its descriptor", desc.digest)));
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
        if actual != desc.digest {
            return Err(OciError::DigestMismatch { digest: desc.digest.clone(), actual });
        }
        Ok(())
    }

    async fn get(&mut self, image: &ImageRef, url: &str, accept: Option<&str>) -> Result<reqwest::Response, OciError> {
        for attempt in 0..2 {
            let mut req = self.http.get(url);
            if let Some(a) = accept {
                req = req.header("Accept", a);
            }
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            } else if let (Some(u), Some(p)) = (&self.creds.username, &self.creds.password) {
                req = req.basic_auth(u, Some(p));
            }
            let resp = req.send().await?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                self.authenticate(image, &challenge).await?;
                continue;
            }
            if !resp.status().is_success() {
                return Err(OciError::Status { status: resp.status().as_u16(), what: url.to_owned() });
            }
            return Ok(resp);
        }
        Err(OciError::Auth("registry rejected credentials".into()))
    }

    async fn authenticate(&mut self, image: &ImageRef, challenge: &str) -> Result<(), OciError> {
        let Some(params) = challenge.strip_prefix("Bearer ") else {
            // Basic: credentials are sent on the retry.
            if self.creds.username.is_none() {
                return Err(OciError::Auth("registry requires credentials".into()));
            }
            return Ok(());
        };
        let fields = parse_challenge(params);
        let realm = fields.iter().find(|(k, _)| k == "realm").map(|(_, v)| v.clone()).ok_or_else(|| OciError::Auth("no realm".into()))?;
        let realm_url = url::Url::parse(&realm).map_err(|_| OciError::Auth("bad realm".into()))?;
        if realm_url.scheme() != "https" {
            return Err(OciError::Auth("token realm must be HTTPS".into()));
        }
        let mut req = self.http.get(realm_url);
        let mut query: Vec<(String, String)> = Vec::new();
        for key in ["service", "scope"] {
            if let Some((_, v)) = fields.iter().find(|(k, _)| k == key) {
                query.push((key.to_owned(), v.clone()));
            }
        }
        if !query.iter().any(|(k, _)| k == "scope") {
            query.push(("scope".into(), format!("repository:{}:pull", image.repository)));
        }
        req = req.query(&query);
        if let (Some(u), Some(p)) = (&self.creds.username, &self.creds.password) {
            req = req.basic_auth(u, Some(p));
        }
        #[derive(Deserialize)]
        struct Token {
            token: Option<String>,
            access_token: Option<String>,
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(OciError::Auth(format!("token endpoint returned HTTP {}", resp.status().as_u16())));
        }
        let t: Token = serde_json::from_slice(&read_limited(resp, 1024 * 1024).await?)?;
        self.token = t.token.or(t.access_token);
        if self.token.is_none() {
            return Err(OciError::Auth("token endpoint returned no token".into()));
        }
        Ok(())
    }
}

fn is_supported_layer(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip"
    )
}

async fn read_limited(resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, OciError> {
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if out.len() + chunk.len() > limit {
            return Err(OciError::Unsupported("document exceeds size limit".into()));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn verify_digest(digest: &str, bytes: &[u8]) -> Result<(), OciError> {
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if actual != digest {
        return Err(OciError::DigestMismatch { digest: digest.to_owned(), actual });
    }
    Ok(())
}

/// Parses `realm="...",service="...",scope="..."`.
fn parse_challenge(params: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = params.trim();
    while !rest.is_empty() {
        let Some((key, after)) = rest.split_once('=') else { break };
        let key = key.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let after = after.trim_start();
        let (value, remaining) = if let Some(stripped) = after.strip_prefix('"') {
            match stripped.find('"') {
                Some(end) => (stripped[..end].to_owned(), &stripped[end + 1..]),
                None => (stripped.to_owned(), ""),
            }
        } else {
            match after.find(',') {
                Some(end) => (after[..end].trim().to_owned(), &after[end..]),
                None => (after.trim().to_owned(), ""),
            }
        };
        out.push((key, value));
        rest = remaining.trim_start_matches(',').trim_start();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_references() {
        let r = ImageRef::parse("python:3.12-slim").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "library/python", "3.12-slim"));
        let r = ImageRef::parse("ubuntu").unwrap();
        assert_eq!(r.reference, "latest");
        let r = ImageRef::parse("123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app:v1").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("123456789012.dkr.ecr.us-east-1.amazonaws.com", "team/app", "v1"));
        let d = format!("ghcr.io/weftsh/base@sha256:{}", "a".repeat(64));
        let r = ImageRef::parse(&d).unwrap();
        assert_eq!(r.reference, format!("sha256:{}", "a".repeat(64)));
        let r = ImageRef::parse("localhost:5000/x/y:z").unwrap();
        assert_eq!(r.registry, "localhost:5000");
    }

    #[test]
    fn rejects_bad_references() {
        for bad in ["", "https://x/y", "UPPER/case", "a b", "x@sha256:zz", "repo:bad tag", "repo:"] {
            assert!(ImageRef::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parses_bearer_challenges() {
        let f = parse_challenge(r#"realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/python:pull""#);
        assert_eq!(f[0], ("realm".into(), "https://auth.docker.io/token".into()));
        assert_eq!(f[1], ("service".into(), "registry.docker.io".into()));
        assert_eq!(f[2].1, "repository:library/python:pull");
    }

    #[test]
    fn verifies_digests() {
        let d = format!("sha256:{}", hex::encode(Sha256::digest(b"hello")));
        assert!(verify_digest(&d, b"hello").is_ok());
        assert!(verify_digest(&d, b"hellO").is_err());
    }
}
