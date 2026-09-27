//! Connecting to upstreams on a sandbox's behalf.
//!
//! Name-based traffic (TLS SNI, HTTP Host) is resolved here, never taken from
//! the sandbox's original destination address, and every address the gateway
//! connects to must pass `check_resolved`. Resolving once and connecting to
//! the checked address leaves no window for DNS rebinding.
//!
//! [`DevRouting`] lets development setups and integration tests point
//! allowlisted names and addresses at local servers. It only exists when the
//! gateway runs with `--dev`, and it only applies after the policy has
//! allowed the name or address.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use weft_netpolicy::{CompiledPolicy, Decision, DenyReason};

use crate::audit::reason;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("destination denied: {}", .0.as_str())]
    Denied(DenyReason),
    #[error("resolving {host} failed: {source}")]
    Resolve { host: String, source: io::Error },
    #[error("{host} has no addresses")]
    NoAddresses { host: String },
    #[error("connecting to {addr} failed: {source}")]
    Connect { addr: SocketAddr, source: io::Error },
    #[error("timed out connecting upstream")]
    Timeout,
    #[error("upstream TLS handshake failed: {0}")]
    Tls(io::Error),
}

impl ConnectError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Denied(r) => r.as_str(),
            Self::Resolve { .. } | Self::NoAddresses { .. } => reason::RESOLVE_FAILED,
            Self::Connect { .. } | Self::Timeout => reason::CONNECT_FAILED,
            Self::Tls(_) => reason::UPSTREAM_TLS_FAILED,
        }
    }
}

/// Development-only routing overrides. Constructed only from `--dev` flags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DevRouting {
    /// Allowed hostname to the address actually dialled.
    pub resolve: HashMap<String, SocketAddr>,
    /// Allowed original destination to the address actually dialled.
    pub redirect: HashMap<SocketAddr, SocketAddr>,
}

pub struct Upstreams {
    connect_timeout: Duration,
    tls: TlsConnector,
    dev: Option<DevRouting>,
}

impl Upstreams {
    pub fn new(
        connect_timeout: Duration,
        tls: Arc<rustls::ClientConfig>,
        dev: Option<DevRouting>,
    ) -> Self {
        Self {
            connect_timeout,
            tls: TlsConnector::from(tls),
            dev,
        }
    }

    /// Connects to `host:port`. The caller has already checked the name with
    /// `check_name`; this checks every address it dials with `check_resolved`.
    pub async fn connect_name(
        &self,
        policy: &CompiledPolicy,
        host: &str,
        port: u16,
    ) -> Result<(TcpStream, SocketAddr), ConnectError> {
        let deadline = Instant::now() + self.connect_timeout;
        if let Some(addr) = self.dev.as_ref().and_then(|d| d.resolve.get(host)) {
            tracing::debug!(host, %addr, "dev routing override");
            return dial(*addr, deadline).await.map(|s| (s, *addr));
        }

        let resolved = timeout_at(deadline, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| ConnectError::Timeout)?
            .map_err(|source| ConnectError::Resolve {
                host: host.to_owned(),
                source,
            })?;
        let mut candidates = Vec::new();
        let mut first_denial = None;
        for addr in resolved {
            match policy.check_resolved(addr.ip(), port) {
                Decision::Allow => candidates.push(addr),
                Decision::Deny(r) => {
                    first_denial.get_or_insert(r);
                }
            }
        }
        if candidates.is_empty() {
            return Err(match first_denial {
                Some(r) => ConnectError::Denied(r),
                None => ConnectError::NoAddresses {
                    host: host.to_owned(),
                },
            });
        }
        // Most VPCs are IPv4-only; try those first.
        candidates.sort_by_key(|a| !a.is_ipv4());
        let mut last_err = None;
        for addr in candidates {
            match dial(addr, deadline).await {
                Ok(stream) => return Ok((stream, addr)),
                Err(ConnectError::Timeout) => return Err(ConnectError::Timeout),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(ConnectError::Timeout))
    }

    /// Connects to exactly `addr`, which the caller has checked with `check_ip`.
    pub async fn connect_addr(
        &self,
        addr: SocketAddr,
    ) -> Result<(TcpStream, SocketAddr), ConnectError> {
        let deadline = Instant::now() + self.connect_timeout;
        let target = self
            .dev
            .as_ref()
            .and_then(|d| d.redirect.get(&addr))
            .copied()
            .unwrap_or(addr);
        if target != addr {
            tracing::debug!(%addr, %target, "dev routing override");
        }
        dial(target, deadline).await.map(|s| (s, target))
    }

    /// Starts verified TLS to `host` over `tcp`, offering only HTTP/1.1.
    pub async fn tls(
        &self,
        host: &str,
        tcp: TcpStream,
    ) -> Result<TlsStream<TcpStream>, ConnectError> {
        let name = ServerName::try_from(host.to_owned())
            .map_err(|e| ConnectError::Tls(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        tokio::time::timeout(self.connect_timeout, self.tls.connect(name, tcp))
            .await
            .map_err(|_| ConnectError::Timeout)?
            .map_err(ConnectError::Tls)
    }
}

async fn dial(addr: SocketAddr, deadline: Instant) -> Result<TcpStream, ConnectError> {
    let stream = timeout_at(deadline, TcpStream::connect(addr))
        .await
        .map_err(|_| ConnectError::Timeout)?
        .map_err(|source| ConnectError::Connect { addr, source })?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// TLS settings for upstream connections: Mozilla's roots (plus, in
/// development, extra roots), HTTP/1.1 only.
pub fn client_tls_config(
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra_roots {
        roots.add(cert.clone())?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use weft_netpolicy::EgressPolicy;

    fn policy(json: &str) -> CompiledPolicy {
        let p: EgressPolicy = serde_json::from_str(json).unwrap();
        CompiledPolicy::compile(&p).unwrap()
    }

    fn upstreams(dev: Option<DevRouting>) -> Upstreams {
        Upstreams::new(Duration::from_secs(2), client_tls_config(&[]).unwrap(), dev)
    }

    #[tokio::test]
    async fn names_resolving_to_loopback_are_denied() {
        let p = policy(r#"{"allow":[{"host":"*"}]}"#);
        let err = upstreams(None)
            .connect_name(&p, "localhost", 80)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConnectError::Denied(DenyReason::ForbiddenAddress)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn dev_routing_applies_to_names_and_addresses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let dev = DevRouting {
            resolve: HashMap::from([("api.example.com".to_owned(), local)]),
            redirect: HashMap::from([("10.9.8.7:5432".parse().unwrap(), local)]),
        };
        let u = upstreams(Some(dev));
        let p = policy(r#"{"allow":[{"host":"api.example.com"}]}"#);
        let (_, addr) = u.connect_name(&p, "api.example.com", 443).await.unwrap();
        assert_eq!(addr, local);
        let (_, addr) = u
            .connect_addr("10.9.8.7:5432".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(addr, local);
    }
}
