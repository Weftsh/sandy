//! One sandbox connection, from PROXY header to close.
//!
//! Order matters: the PROXY header names a sandbox, but the gateway only
//! trusts that claim after the control plane confirms the sandbox runs on
//! the host the TCP connection came from. Only then does it read the
//! sandbox's own bytes, classify them and pick a path.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at, Instant};
use tokio_rustls::TlsAcceptor;
use weft_netpolicy::policy::normalize_hostname;
use weft_netpolicy::proxy_protocol::MAX_HEADER_LEN;
use weft_netpolicy::{CompiledPolicy, DenyReason, ProxyHeader};

use crate::audit::{self, reason, Protocol as AuditProtocol, SharedRecord};
use crate::classify::{classify, Protocol};
use crate::io::{idle_watchdog, Metered, Rewind, Stats};
use crate::proxy::{self, Mode};
use crate::server::Gateway;

pub const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type ClientStream = Metered<TcpStream>;

/// What every path needs to know about the connection.
pub(crate) struct ConnCtx {
    pub gw: Arc<Gateway>,
    pub sandbox_id: String,
    /// The TCP peer: the host agent's address, canonicalized.
    pub peer_ip: IpAddr,
    /// The sandbox's original destination.
    pub destination: SocketAddr,
    pub record: SharedRecord,
}

pub(crate) async fn handle(gw: Arc<Gateway>, tcp: TcpStream, peer: SocketAddr) {
    let stats = Arc::new(Stats::new());
    let record = SharedRecord::new(peer);
    let stream = Metered::new(tcp, stats.clone());
    let idle = gw.idle_timeout;
    tokio::select! {
        () = serve(gw, stream, peer, &stats, record.clone()) => {}
        () = idle_watchdog(&stats, idle) => {
            tracing::debug!(%peer, "closing idle connection");
        }
    }
    audit::connection(&record.lock(), &stats);
}

async fn serve(
    gw: Arc<Gateway>,
    mut stream: ClientStream,
    peer: SocketAddr,
    stats: &Stats,
    record: SharedRecord,
) {
    let (header, header_len, buf) = match read_proxy_header(&mut stream).await {
        Ok(parts) => parts,
        Err(e) => {
            tracing::warn!(%peer, error = %e, "rejected connection without a valid PROXY header");
            record.lock().deny(reason::BAD_PROXY_HEADER);
            return;
        }
    };
    stats.discount_up(header_len as u64);
    let ProxyHeader {
        source,
        destination,
        sandbox_id,
    } = header;
    {
        let mut rec = record.lock();
        rec.sandbox_id = Some(sandbox_id.clone());
        rec.source = Some(source);
        rec.destination = Some(destination);
    }

    let sandbox = match gw.policies.lookup(&sandbox_id).await {
        Ok(s) => s,
        Err(e) => {
            record.lock().deny(e.reason());
            return;
        }
    };
    let peer_ip = peer.ip().to_canonical();
    if sandbox.host_ip != peer_ip {
        tracing::warn!(
            sandboxId = %sandbox_id,
            %peer,
            expected = %sandbox.host_ip,
            "connection claims a sandbox that does not run on its host"
        );
        record.lock().deny(reason::HOST_MISMATCH);
        return;
    }
    let Some(_permit) = gw.limits.try_sandbox(&sandbox_id) else {
        record.lock().deny(reason::TOO_MANY_CONNECTIONS);
        return;
    };

    let mut buf = buf;
    let protocol = match classify(&mut stream, &mut buf).await {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(sandboxId = %sandbox_id, error = %e, "connection failed before classification");
            return;
        }
    };
    let prefix = buf.freeze();
    let ctx = Arc::new(ConnCtx {
        gw,
        sandbox_id,
        peer_ip,
        destination,
        record,
    });
    let policy = &sandbox.policy;
    match protocol {
        Protocol::Tls { server_name } => tls(ctx, policy, server_name, stream, prefix).await,
        Protocol::Http => {
            ctx.record.lock().protocol = AuditProtocol::Http;
            proxy::serve(ctx.clone(), Mode::Plain, Rewind::new(stream, prefix)).await;
        }
        Protocol::Opaque { why } => {
            tracing::debug!(sandboxId = %ctx.sandbox_id, ?why, "opaque connection");
            opaque(ctx, policy, stream, prefix).await;
        }
    }
}

async fn tls(
    ctx: Arc<ConnCtx>,
    policy: &CompiledPolicy,
    server_name: String,
    stream: ClientStream,
    prefix: Bytes,
) {
    let port = ctx.destination.port();
    let host = normalize_hostname(&server_name);
    {
        let mut rec = ctx.record.lock();
        rec.protocol = AuditProtocol::Tls;
        rec.destination_host = Some(host.clone().unwrap_or(server_name));
    }
    let Some(host) = host else {
        ctx.record.lock().deny(DenyReason::NotAllowed.as_str());
        return;
    };
    if !ctx.record.lock().check(policy.check_name(&host, port)) {
        return;
    }

    if port == 443 && policy.credential_for(&host).is_some() {
        ctx.record.lock().intercepted = true;
        intercept(ctx, host, Rewind::new(stream, prefix)).await;
        return;
    }

    let (mut upstream, addr) = match ctx.gw.upstreams.connect_name(policy, &host, port).await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(sandboxId = %ctx.sandbox_id, host, error = %e, "upstream connect failed");
            ctx.record.lock().deny(e.reason());
            return;
        }
    };
    {
        let mut rec = ctx.record.lock();
        rec.upstream = Some(addr);
        rec.allow();
    }
    let mut client = Rewind::new(stream, prefix);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn intercept(ctx: Arc<ConnCtx>, host: String, stream: Rewind<ClientStream>) {
    let config = match ctx.gw.ca.server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(host, error = %e, "cannot issue interception certificate");
            ctx.record.lock().deny(reason::CERTIFICATE_ERROR);
            return;
        }
    };
    let accepted = timeout(
        CLIENT_TLS_HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(config).accept(stream),
    )
    .await;
    let tls = match accepted {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            tracing::debug!(sandboxId = %ctx.sandbox_id, host, error = %e, "sandbox TLS handshake failed");
            ctx.record.lock().deny(reason::TLS_HANDSHAKE_FAILED);
            return;
        }
        Err(_) => {
            ctx.record.lock().deny(reason::TLS_HANDSHAKE_FAILED);
            return;
        }
    };
    proxy::serve(ctx, Mode::Intercept { host }, tls).await;
}

async fn opaque(ctx: Arc<ConnCtx>, policy: &CompiledPolicy, stream: ClientStream, prefix: Bytes) {
    let dst = ctx.destination;
    {
        let mut rec = ctx.record.lock();
        rec.protocol = AuditProtocol::Opaque;
        if !rec.check(policy.check_ip(dst.ip(), dst.port())) {
            return;
        }
    }
    let (mut upstream, addr) = match ctx.gw.upstreams.connect_addr(dst).await {
        Ok(c) => c,
        Err(e) => {
            ctx.record.lock().deny(e.reason());
            return;
        }
    };
    {
        let mut rec = ctx.record.lock();
        rec.upstream = Some(addr);
        rec.allow();
    }
    let mut client = Rewind::new(stream, prefix);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

#[derive(Debug, thiserror::Error)]
enum HeaderError {
    #[error(transparent)]
    Protocol(#[from] weft_netpolicy::ProxyProtocolError),
    #[error("connection closed before a complete PROXY header")]
    Eof,
    #[error("timed out waiting for the PROXY header")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Reads the PROXY v2 header. Returns it, its length, and any bytes read past
/// it, which belong to the sandbox.
async fn read_proxy_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(ProxyHeader, usize, BytesMut), HeaderError> {
    let deadline = Instant::now() + PROXY_HEADER_TIMEOUT;
    let mut buf = BytesMut::with_capacity(MAX_HEADER_LEN);
    let mut chunk = [0u8; 256];
    loop {
        if let Some((header, used)) = ProxyHeader::decode(&buf)? {
            let rest = buf.split_off(used);
            return Ok((header, used, rest));
        }
        let room = MAX_HEADER_LEN
            .saturating_sub(buf.len())
            .clamp(1, chunk.len());
        let n = timeout_at(deadline, stream.read(&mut chunk[..room]))
            .await
            .map_err(|_| HeaderError::Timeout)??;
        if n == 0 {
            return Err(HeaderError::Eof);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn header() -> Vec<u8> {
        ProxyHeader {
            source: "10.200.0.2:40000".parse().unwrap(),
            destination: "140.82.112.3:443".parse().unwrap(),
            sandbox_id: "sbx1".into(),
        }
        .encode()
        .unwrap()
    }

    #[tokio::test]
    async fn reads_a_header_split_across_segments_and_keeps_the_rest() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let bytes = header();
        tokio::spawn(async move {
            client.write_all(&bytes[..10]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client.write_all(&bytes[10..]).await.unwrap();
            client.write_all(b"\x16\x03\x01").await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let (h, len, rest) = read_proxy_header(&mut server).await.unwrap();
        assert_eq!(h.sandbox_id, "sbx1");
        assert_eq!(len, header().len());
        // The trailing bytes may or may not have arrived in the same read.
        assert!(rest.is_empty() || &rest[..] == b"\x16\x03\x01");
    }

    #[tokio::test]
    async fn rejects_non_proxy_bytes_and_eof() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(
            read_proxy_header(&mut server).await,
            Err(HeaderError::Protocol(
                weft_netpolicy::ProxyProtocolError::BadSignature
            ))
        ));
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&header()[..20]).await.unwrap();
        drop(client);
        assert!(matches!(
            read_proxy_header(&mut server).await,
            Err(HeaderError::Eof)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_slow_headers() {
        let (_client, mut server) = tokio::io::duplex(4096);
        assert!(matches!(
            read_proxy_header(&mut server).await,
            Err(HeaderError::Timeout)
        ));
    }
}
