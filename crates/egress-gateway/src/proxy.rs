//! HTTP/1.1 proxying, for plain HTTP and for the credential proxy.
//!
//! hyper parses each request from the sandbox, so every request on a
//! keep-alive connection is checked, not just the first. A connection is
//! pinned to the host of its first allowed request: the upstream connection
//! was opened for that host, so a later request naming another host gets
//! `421 Misdirected Request` (the client may retry on a new connection, which
//! is then checked on its own) rather than being sent to the wrong server.
//!
//! In credential mode the sandbox's TLS has been terminated with a leaf for
//! the SNI host; every request must name that host, any client-supplied copy
//! of the credential header is removed and the real value is set before the
//! request goes upstream over verified TLS. Bodies are streamed both ways.
//!
//! `Connection: upgrade` requests (WebSocket) are checked like any other; on
//! `101 Switching Protocols` both sides are handed back to the connection
//! task, which splices them raw. The upstream remains the checked host.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use weft_netpolicy::{CompiledPolicy, CredentialRule, Decision};

use crate::audit::{self, reason, RequestRecord};
use crate::conn::ConnCtx;
use crate::http_head::{parse_authority, TargetHost};
use crate::io::AbortOnDrop;
use crate::upstream::ConnectError;

type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Also bounds how long an idle keep-alive connection waits for its next
/// request; hyper runs the same timer between requests.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BUF: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;

/// Which kind of HTTP connection this is.
pub(crate) enum Mode {
    /// Plain HTTP; the original destination port applies.
    Plain,
    /// The credential proxy for this (normalized) host, on port 443.
    Intercept { host: String },
}

struct UpstreamConn {
    sender: SendRequest<Incoming>,
    _task: AbortOnDrop<()>,
}

struct PendingUpgrade {
    client: OnUpgrade,
    upstream: OnUpgrade,
    /// Keeps the upstream connection task alive until it hands over its IO.
    _conn: Option<UpstreamConn>,
}

struct Session {
    ctx: Arc<ConnCtx>,
    mode: Mode,
    pinned: Mutex<Option<TargetHost>>,
    upstream: tokio::sync::Mutex<Option<UpstreamConn>>,
    upgrade: Mutex<Option<PendingUpgrade>>,
}

/// Serves HTTP/1.1 requests from the sandbox on `io` until it closes, then
/// splices an upgraded connection if one was switched.
pub(crate) async fn serve<S>(ctx: Arc<ConnCtx>, mode: Mode, io: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session = Arc::new(Session {
        ctx,
        mode,
        pinned: Mutex::new(None),
        upstream: tokio::sync::Mutex::new(None),
        upgrade: Mutex::new(None),
    });
    let service = {
        let session = session.clone();
        service_fn(move |req| {
            let session = session.clone();
            async move { Ok::<_, Infallible>(session.handle(req).await) }
        })
    };
    let result = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_BUF)
        .max_headers(MAX_HEADERS)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await;
    if let Err(e) = result {
        tracing::debug!(error = %e, "sandbox HTTP connection ended with an error");
    }

    let pending = lock(&session.upgrade).take();
    // The service may still hold a reference; the upstream is no longer needed.
    session.upstream.lock().await.take();
    if let Some(pending) = pending {
        let (client, upstream) = tokio::join!(pending.client, pending.upstream);
        match (client, upstream) {
            (Ok(client), Ok(upstream)) => {
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(client),
                    &mut TokioIo::new(upstream),
                )
                .await;
            }
            (c, u) => tracing::debug!(
                client_ok = c.is_ok(),
                upstream_ok = u.is_ok(),
                "upgrade failed"
            ),
        }
    }
}

/// Why a request was not forwarded.
struct Refusal {
    status: StatusCode,
    reason: &'static str,
}

impl Refusal {
    fn new(status: StatusCode, reason: &'static str) -> Self {
        Self { status, reason }
    }

    fn forbidden(reason: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, reason)
    }

    fn misdirected() -> Self {
        Self::new(StatusCode::MISDIRECTED_REQUEST, reason::MISDIRECTED_REQUEST)
    }

    fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason::MALFORMED_REQUEST)
    }

    fn from_connect(e: &ConnectError) -> Self {
        let status = match e {
            ConnectError::Denied(_) => StatusCode::FORBIDDEN,
            ConnectError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, e.reason())
    }

    fn response(&self) -> Response<ProxyBody> {
        let text = format!(
            "weft egress gateway: {} ({})\n",
            self.status.canonical_reason().unwrap_or("refused"),
            self.reason
        );
        let mut resp = Response::new(full(text));
        *resp.status_mut() = self.status;
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        h.insert(
            "x-weft-egress-reason",
            HeaderValue::from_static(self.reason),
        );
        resp
    }
}

/// Facts about one request for its audit record.
#[derive(Default)]
struct RequestFacts {
    host: String,
    credential_injected: bool,
}

impl Session {
    async fn handle(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let started = Instant::now();
        let method: String = req.method().as_str().chars().take(32).collect();
        let mut facts = RequestFacts::default();
        let (resp, outcome) = match self.forward(req, &mut facts).await {
            Ok(resp) => (resp, Ok(())),
            Err(refusal) => (refusal.response(), Err(refusal.reason)),
        };
        {
            let mut rec = self.ctx.record.lock();
            rec.requests += 1;
            rec.credential_injected |= facts.credential_injected;
            if rec.destination_host.is_none() && !facts.host.is_empty() {
                rec.destination_host = Some(facts.host.clone());
            }
            match outcome {
                Ok(()) => rec.allow(),
                Err(r) => rec.deny(r),
            }
        }
        audit::request(&RequestRecord {
            sandbox_id: &self.ctx.sandbox_id,
            intercepted: matches!(self.mode, Mode::Intercept { .. }),
            method: &method,
            host: &facts.host,
            status: resp.status().as_u16(),
            outcome,
            credential_injected: facts.credential_injected,
            duration: started.elapsed(),
        });
        resp
    }

    async fn forward(
        &self,
        mut req: Request<Incoming>,
        facts: &mut RequestFacts,
    ) -> Result<Response<ProxyBody>, Refusal> {
        if req.method() == Method::CONNECT {
            return Err(Refusal::new(
                StatusCode::METHOD_NOT_ALLOWED,
                reason::METHOD_NOT_ALLOWED,
            ));
        }
        let authority = request_authority(&req)?;
        let (target, port) = parse_authority(&authority).ok_or_else(Refusal::bad_request)?;
        facts.host = target.to_string();

        // Re-read the policy (normally from cache) so revocations reach
        // long-lived keep-alive connections.
        let sandbox = self
            .ctx
            .gw
            .policies
            .lookup(&self.ctx.sandbox_id)
            .await
            .map_err(|e| Refusal::forbidden(e.reason()))?;
        if sandbox.host_ip != self.ctx.peer_ip {
            return Err(Refusal::forbidden(reason::HOST_MISMATCH));
        }
        let policy = &sandbox.policy;
        let credential = self.check(policy, &target, port)?;

        {
            let mut pinned = lock(&self.pinned);
            match pinned.as_ref() {
                None => *pinned = Some(target.clone()),
                Some(p) if *p != target => return Err(Refusal::misdirected()),
                Some(_) => {}
            }
        }

        let upgrading = is_upgrade(req.headers());
        let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));
        let (parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let uri: Uri = path.parse().map_err(|_| Refusal::bad_request())?;
        let mut headers = parts.headers;
        strip_hop_by_hop(&mut headers, upgrading);
        headers.insert(
            header::HOST,
            HeaderValue::from_str(&authority).map_err(|_| Refusal::bad_request())?,
        );
        if let Some(rule) = &credential {
            self.inject(rule, &mut headers).await?;
        }
        let mut out = Request::new(body);
        *out.method_mut() = parts.method;
        *out.uri_mut() = uri;
        *out.version_mut() = Version::HTTP_11;
        *out.headers_mut() = headers;

        let mut resp = self.send(policy, &target, out).await?;
        facts.credential_injected = credential.is_some();

        match client_upgrade {
            Some(client) if resp.status() == StatusCode::SWITCHING_PROTOCOLS => {
                let upstream = hyper::upgrade::on(&mut resp);
                let conn = self.upstream.lock().await.take();
                *lock(&self.upgrade) = Some(PendingUpgrade {
                    client,
                    upstream,
                    _conn: conn,
                });
            }
            _ => strip_hop_by_hop(resp.headers_mut(), false),
        }
        Ok(resp.map(BodyExt::boxed))
    }

    /// Applies the policy to one request. Returns the credential to inject.
    fn check(
        &self,
        policy: &CompiledPolicy,
        target: &TargetHost,
        port: Option<u16>,
    ) -> Result<Option<CredentialRule>, Refusal> {
        let dst = self.ctx.destination;
        let decision = match &self.mode {
            Mode::Plain => {
                if port.is_some_and(|p| p != dst.port()) {
                    return Err(Refusal::misdirected());
                }
                match target {
                    TargetHost::Name(name) => policy.check_name(name, dst.port()),
                    // An address literal must be where the sandbox connected.
                    TargetHost::Ip(ip) if ip.to_canonical() == dst.ip().to_canonical() => {
                        policy.check_ip(dst.ip(), dst.port())
                    }
                    TargetHost::Ip(_) => return Err(Refusal::misdirected()),
                }
            }
            Mode::Intercept { host } => {
                let same_host = matches!(target, TargetHost::Name(n) if n == host);
                if !same_host || port.is_some_and(|p| p != 443) {
                    return Err(Refusal::misdirected());
                }
                policy.check_name(host, 443)
            }
        };
        if let Decision::Deny(r) = decision {
            return Err(Refusal::forbidden(r.as_str()));
        }
        Ok(match &self.mode {
            Mode::Plain => None,
            Mode::Intercept { host } => policy.credential_for(host).cloned(),
        })
    }

    async fn inject(&self, rule: &CredentialRule, headers: &mut HeaderMap) -> Result<(), Refusal> {
        let name = HeaderName::from_bytes(rule.header.as_bytes())
            .map_err(|_| Refusal::new(StatusCode::BAD_GATEWAY, reason::CREDENTIAL_UNAVAILABLE))?;
        headers.remove(&name);
        let value = self.ctx.gw.secrets.header_value(rule).await.map_err(|e| {
            tracing::warn!(
                sandboxId = %self.ctx.sandbox_id,
                host = %rule.host,
                secretId = %rule.secret_id,
                error = %e,
                "credential unavailable"
            );
            Refusal::new(StatusCode::BAD_GATEWAY, reason::CREDENTIAL_UNAVAILABLE)
        })?;
        headers.insert(name, value);
        Ok(())
    }

    /// Sends on the pinned upstream connection, opening it if needed. A
    /// request that was never written (the idle upstream closed first) is
    /// retried once on a fresh connection.
    async fn send(
        &self,
        policy: &CompiledPolicy,
        target: &TargetHost,
        req: Request<Incoming>,
    ) -> Result<Response<Incoming>, Refusal> {
        let mut slot = self.upstream.lock().await;
        let mut req = req;
        let mut retried = false;
        loop {
            let reusable = match slot.as_mut() {
                Some(conn) => conn.sender.ready().await.is_ok(),
                None => false,
            };
            if !reusable {
                *slot = None;
                *slot = Some(self.connect(policy, target).await?);
            }
            let Some(conn) = slot.as_mut() else {
                return Err(Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    reason::UPSTREAM_ERROR,
                ));
            };
            match conn.sender.try_send_request(req).await {
                Ok(resp) => return Ok(resp),
                Err(mut e) => {
                    *slot = None;
                    match e.take_message() {
                        Some(unsent) if !retried => {
                            retried = true;
                            req = unsent;
                        }
                        _ => {
                            tracing::debug!(error = %e.into_error(), "upstream request failed");
                            return Err(Refusal::new(
                                StatusCode::BAD_GATEWAY,
                                reason::UPSTREAM_ERROR,
                            ));
                        }
                    }
                }
            }
        }
    }

    async fn connect(
        &self,
        policy: &CompiledPolicy,
        target: &TargetHost,
    ) -> Result<UpstreamConn, Refusal> {
        let gw = &self.ctx.gw;
        let port = match &self.mode {
            Mode::Plain => self.ctx.destination.port(),
            Mode::Intercept { .. } => 443,
        };
        let connected = match target {
            TargetHost::Name(name) => gw.upstreams.connect_name(policy, name, port).await,
            TargetHost::Ip(_) => gw.upstreams.connect_addr(self.ctx.destination).await,
        };
        let (tcp, addr) = connected.map_err(|e| {
            tracing::debug!(sandboxId = %self.ctx.sandbox_id, host = %target, error = %e, "upstream connect failed");
            Refusal::from_connect(&e)
        })?;
        self.ctx.record.lock().upstream = Some(addr);
        let handshake = match &self.mode {
            Mode::Plain => handshake(tcp).await,
            Mode::Intercept { host } => {
                let tls = gw.upstreams.tls(host, tcp).await.map_err(|e| {
                    tracing::warn!(sandboxId = %self.ctx.sandbox_id, host, error = %e, "upstream TLS failed");
                    Refusal::from_connect(&e)
                })?;
                handshake(tls).await
            }
        };
        handshake.map_err(|e| {
            tracing::debug!(error = %e, "upstream HTTP handshake failed");
            Refusal::new(StatusCode::BAD_GATEWAY, reason::UPSTREAM_ERROR)
        })
    }
}

async fn handshake<I>(io: I) -> Result<UpstreamConn, hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(MAX_BUF)
        .handshake(TokioIo::new(io))
        .await?;
    let task = tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "upstream HTTP connection ended with an error");
        }
    });
    Ok(UpstreamConn {
        sender,
        _task: AbortOnDrop(task),
    })
}

/// The request's authority: the single Host header, or the authority of an
/// absolute-form target. When both are present they must agree.
fn request_authority<B>(req: &Request<B>) -> Result<String, Refusal> {
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(Refusal::bad_request());
    }
    let host = host
        .map(|v| {
            v.to_str()
                .map(str::trim)
                .map_err(|_| Refusal::bad_request())
        })
        .transpose()?;
    let from_uri = req.uri().authority().map(|a| a.as_str());
    match (host, from_uri) {
        (Some(h), Some(u)) if !h.eq_ignore_ascii_case(u) => Err(Refusal::bad_request()),
        (Some(h), _) => Ok(h.to_owned()),
        (None, Some(u)) => Ok(u.to_owned()),
        (None, None) => Err(Refusal::bad_request()),
    }
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && connection_tokens(headers).any(|t| t.eq_ignore_ascii_case("upgrade"))
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Removes hop-by-hop headers (RFC 9110 section 7.6.1), keeping the upgrade
/// handshake when `keep_upgrade` is set.
fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let upgrade = keep_upgrade
        .then(|| headers.get(header::UPGRADE).cloned())
        .flatten();
    let listed: Vec<HeaderName> = connection_tokens(headers)
        .filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHORIZATION,
        header::PROXY_AUTHENTICATE,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
    if let Some(upgrade) = upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, upgrade);
    }
}

fn full(text: String) -> ProxyBody {
    Full::new(Bytes::from(text))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_hop_by_hop_and_connection_listed_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Secret-Hop"),
        );
        h.insert("x-secret-hop", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        h.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic x"),
        );
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        strip_hop_by_hop(&mut h, false);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key(header::ACCEPT));
    }

    #[test]
    fn keeps_the_upgrade_handshake_when_asked() {
        let mut h = HeaderMap::new();
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(is_upgrade(&h));
        strip_hop_by_hop(&mut h, true);
        assert_eq!(h[header::CONNECTION], "upgrade");
        assert_eq!(h[header::UPGRADE], "websocket");
        strip_hop_by_hop(&mut h, false);
        assert!(h.is_empty());
    }

    #[test]
    fn authority_comes_from_one_host_or_the_absolute_uri() {
        let req = |uri: &str, hosts: &[&str]| {
            let mut b = Request::builder().uri(uri);
            for h in hosts {
                b = b.header(header::HOST, *h);
            }
            b.body(()).unwrap()
        };
        assert_eq!(
            request_authority(&req("/", &["a.example.com"])).ok(),
            Some("a.example.com".into())
        );
        assert_eq!(
            request_authority(&req("http://a.example.com/", &[])).ok(),
            Some("a.example.com".into())
        );
        assert_eq!(
            request_authority(&req("http://A.example.com/", &["a.example.com"])).ok(),
            Some("a.example.com".into())
        );
        assert!(request_authority(&req("http://b.example.com/", &["a.example.com"])).is_err());
        assert!(request_authority(&req("/", &["a.example.com", "b.example.com"])).is_err());
        assert!(request_authority(&req("/", &[])).is_err());
    }
}
