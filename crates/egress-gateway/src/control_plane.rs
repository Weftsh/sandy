//! Fetching sandbox egress policies from the control plane.
//!
//! `GET {base}/internal/v1/sandboxes/{id}/egress` returns the sandbox's
//! policy and the IP of the host running it. Answers are cached briefly:
//! allowed lookups for 30 seconds, so policy changes and sandbox moves take
//! effect quickly, and failures for 5 seconds, so a sandbox hammering a dead
//! destination cannot hammer the control plane too. Any failure denies.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use weft_awsauth::{HeaderCache, AUTH_HEADER};
use weft_netpolicy::{CompiledPolicy, EgressPolicy};

use crate::audit::reason;
use crate::cache::TtlCache;

pub const POSITIVE_TTL: Duration = Duration::from_secs(30);
pub const NEGATIVE_TTL: Duration = Duration::from_secs(5);
const CACHE_ENTRIES: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// A policy of 256 rules is a few tens of KiB at most.
const MAX_BODY: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EgressResponse {
    sandbox_id: String,
    host_ip: IpAddr,
    policy: EgressPolicy,
}

/// A sandbox's policy and where it runs.
#[derive(Debug)]
pub struct SandboxPolicy {
    pub sandbox_id: String,
    /// The host the sandbox is assigned to; connections for it must come
    /// from this address.
    pub host_ip: IpAddr,
    pub policy: CompiledPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    #[error("the control plane does not know this sandbox")]
    UnknownSandbox,
    #[error("the sandbox's policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("the control plane is unavailable: {0}")]
    Unavailable(String),
}

impl LookupError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UnknownSandbox => reason::UNKNOWN_SANDBOX,
            Self::InvalidPolicy(_) => reason::INVALID_POLICY,
            Self::Unavailable(_) => reason::CONTROL_PLANE_ERROR,
        }
    }
}

type Lookup = Result<Arc<SandboxPolicy>, LookupError>;

pub struct PolicyClient {
    base_url: String,
    http: reqwest::Client,
    auth: HeaderCache,
    cache: TtlCache<String, Lookup>,
}

impl PolicyClient {
    pub fn new(base_url: &str, auth: HeaderCache) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            // The control plane is internal; never route it through a proxy
            // from the environment.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
            auth,
            cache: TtlCache::new(CACHE_ENTRIES),
        })
    }

    /// The sandbox's policy, from cache when fresh. `sandbox_id` comes from a
    /// decoded PROXY header, which only admits `[A-Za-z0-9_-]`.
    pub async fn lookup(&self, sandbox_id: &str) -> Lookup {
        let key = sandbox_id.to_owned();
        if let Some(hit) = self.cache.get(&key) {
            return hit;
        }
        let result = self.fetch(sandbox_id).await;
        if let Err(e) = &result {
            tracing::warn!(sandboxId = sandbox_id, error = %e, "policy lookup failed");
        }
        let ttl = if result.is_ok() {
            POSITIVE_TTL
        } else {
            NEGATIVE_TTL
        };
        self.cache.insert(key, result.clone(), ttl);
        result
    }

    async fn fetch(&self, sandbox_id: &str) -> Lookup {
        let unavailable = |e: &dyn std::fmt::Display| LookupError::Unavailable(e.to_string());
        let header = self.auth.header().await.map_err(|e| unavailable(&e))?;
        let url = format!(
            "{}/internal/v1/sandboxes/{sandbox_id}/egress",
            self.base_url
        );
        let mut resp = self
            .http
            .get(&url)
            .header(AUTH_HEADER, &*header)
            .send()
            .await
            .map_err(|e| unavailable(&e))?;
        match resp.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::NOT_FOUND => return Err(LookupError::UnknownSandbox),
            status @ (reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) => {
                // Sign afresh next time, in case the credentials rotated.
                self.auth.invalidate().await;
                return Err(unavailable(&format!(
                    "control plane rejected our credentials ({status})"
                )));
            }
            status => return Err(unavailable(&format!("unexpected status {status}"))),
        }
        if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
            return Err(unavailable(&"policy response too large"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| unavailable(&e))? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(unavailable(&"policy response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let parsed: EgressResponse =
            serde_json::from_slice(&body).map_err(|e| LookupError::InvalidPolicy(e.to_string()))?;
        if parsed.sandbox_id != sandbox_id {
            return Err(unavailable(&"response is for a different sandbox"));
        }
        let policy = CompiledPolicy::compile(&parsed.policy)
            .map_err(|e| LookupError::InvalidPolicy(e.to_string()))?;
        Ok(Arc::new(SandboxPolicy {
            sandbox_id: parsed.sandbox_id,
            host_ip: parsed.host_ip.to_canonical(),
            policy,
        }))
    }
}
