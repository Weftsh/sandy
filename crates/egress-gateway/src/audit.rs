//! The audit log: one JSON line per sandbox connection and one per proxied
//! HTTP request, written through `tracing` under the `audit` target.
//!
//! Records never contain credential values, request paths, query strings or
//! bodies; only who connected where, what was decided and how much moved.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use weft_netpolicy::Decision;

use crate::io::Stats;

pub const TARGET: &str = "audit";

/// Reasons the gateway itself refuses a connection or request, beyond the
/// policy's own [`weft_netpolicy::DenyReason`]s.
pub mod reason {
    pub const BAD_PROXY_HEADER: &str = "bad_proxy_header";
    pub const UNKNOWN_SANDBOX: &str = "unknown_sandbox";
    pub const INVALID_POLICY: &str = "invalid_policy";
    pub const CONTROL_PLANE_ERROR: &str = "control_plane_error";
    pub const HOST_MISMATCH: &str = "host_mismatch";
    pub const TOO_MANY_CONNECTIONS: &str = "too_many_connections";
    pub const RESOLVE_FAILED: &str = "resolve_failed";
    pub const CONNECT_FAILED: &str = "connect_failed";
    pub const UPSTREAM_TLS_FAILED: &str = "upstream_tls_failed";
    pub const UPSTREAM_ERROR: &str = "upstream_error";
    pub const TLS_HANDSHAKE_FAILED: &str = "tls_handshake_failed";
    pub const CERTIFICATE_ERROR: &str = "certificate_error";
    pub const MALFORMED_REQUEST: &str = "malformed_request";
    pub const MISDIRECTED_REQUEST: &str = "misdirected_request";
    pub const METHOD_NOT_ALLOWED: &str = "method_not_allowed";
    pub const CREDENTIAL_UNAVAILABLE: &str = "credential_unavailable";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Unknown,
    Tls,
    Http,
    Opaque,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Opaque => "opaque",
        }
    }
}

/// What the gateway knows about a connection so far.
#[derive(Clone, Debug)]
pub struct ConnRecord {
    pub peer: SocketAddr,
    pub sandbox_id: Option<String>,
    /// The sandbox's slot address, from the PROXY header.
    pub source: Option<SocketAddr>,
    /// The original destination, from the PROXY header.
    pub destination: Option<SocketAddr>,
    pub destination_host: Option<String>,
    /// The address the gateway actually connected to.
    pub upstream: Option<SocketAddr>,
    pub protocol: Protocol,
    /// `None` until something is decided. See [`ConnRecord::allow`].
    pub outcome: Option<Result<(), &'static str>>,
    pub intercepted: bool,
    pub credential_injected: bool,
    pub requests: u32,
}

impl ConnRecord {
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            peer,
            sandbox_id: None,
            source: None,
            destination: None,
            destination_host: None,
            upstream: None,
            protocol: Protocol::Unknown,
            outcome: None,
            intercepted: false,
            credential_injected: false,
            requests: 0,
        }
    }

    /// Records that traffic reached an upstream. A connection that carried
    /// any allowed traffic is allowed; its denied requests have their own
    /// records.
    pub fn allow(&mut self) {
        self.outcome = Some(Ok(()));
    }

    /// Records a denial unless something was already decided.
    pub fn deny(&mut self, reason: &'static str) {
        if self.outcome.is_none() {
            self.outcome = Some(Err(reason));
        }
    }

    /// Records a policy denial. Returns whether the policy allowed it; an
    /// allowed check is not yet an allowed connection, which needs an upstream.
    pub fn check(&mut self, decision: Decision) -> bool {
        match decision {
            Decision::Allow => true,
            Decision::Deny(r) => {
                self.deny(r.as_str());
                false
            }
        }
    }
}

/// A connection record shared between the connection task and the HTTP
/// service handling its requests.
#[derive(Clone, Debug)]
pub struct SharedRecord(Arc<Mutex<ConnRecord>>);

impl SharedRecord {
    pub fn new(peer: SocketAddr) -> Self {
        Self(Arc::new(Mutex::new(ConnRecord::new(peer))))
    }

    pub fn lock(&self) -> MutexGuard<'_, ConnRecord> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref().map(ToString::to_string).unwrap_or_default()
}

/// Writes the connection's audit line.
pub fn connection(record: &ConnRecord, stats: &Stats) {
    let (decision, reason) = match record.outcome {
        Some(Ok(())) => ("allow", ""),
        Some(Err(r)) => ("deny", r),
        // Closed before any decision, e.g. the sandbox hung up.
        None => ("none", ""),
    };
    tracing::info!(
        target: TARGET,
        event = "connection",
        sandboxId = %opt(&record.sandbox_id),
        peer = %record.peer.ip(),
        src = %opt(&record.source),
        dst = %opt(&record.destination),
        dstHost = %opt(&record.destination_host),
        upstream = %opt(&record.upstream),
        protocol = record.protocol.as_str(),
        decision,
        reason,
        intercepted = record.intercepted,
        credentialInjected = record.credential_injected,
        requests = record.requests,
        bytesUp = stats.bytes_up(),
        bytesDown = stats.bytes_down(),
        durationMs = stats.elapsed().as_millis() as u64,
        "egress connection"
    );
}

/// One proxied HTTP request.
pub struct RequestRecord<'a> {
    pub sandbox_id: &'a str,
    pub intercepted: bool,
    pub method: &'a str,
    pub host: &'a str,
    pub status: u16,
    pub outcome: Result<(), &'static str>,
    pub credential_injected: bool,
    pub duration: Duration,
}

pub fn request(r: &RequestRecord<'_>) {
    let (decision, reason) = match r.outcome {
        Ok(()) => ("allow", ""),
        Err(reason) => ("deny", reason),
    };
    tracing::info!(
        target: TARGET,
        event = "request",
        sandboxId = r.sandbox_id,
        protocol = if r.intercepted { "https" } else { "http" },
        intercepted = r.intercepted,
        method = r.method,
        host = r.host,
        status = r.status,
        decision,
        reason,
        credentialInjected = r.credential_injected,
        durationMs = r.duration.as_millis() as u64,
        "egress request"
    );
}
