//! Data-path tunnel used by the edge proxy.
//!
//! The edge proxy opens a TLS connection and sends
//! `CONNECT <sandboxId>:<port> HTTP/1.1` with the host's bearer token. The
//! tunnel checks the sandbox is running here and splices the connection to
//! that port on the guest. It is plain TCP after the handshake, so envd's
//! Connect streams, file transfers and user services all pass through
//! unchanged. Which paths clients may use is decided by the edge proxy.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::manager::Manager;
use crate::tls::tokens_equal;

const MAX_HEAD: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    pub sandbox_id: String,
    pub port: u16,
    pub token: Option<String>,
}

/// Parses a CONNECT request head. Returns the request and the head length.
pub fn parse_connect(buf: &[u8]) -> Result<Option<(ConnectRequest, usize)>, &'static str> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= MAX_HEAD { Err("request head too large") } else { Ok(None) };
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, target, version) = (first.next(), first.next(), first.next());
    if method != Some("CONNECT") || !matches!(version, Some("HTTP/1.1") | Some("HTTP/1.0")) {
        return Err("expected CONNECT");
    }
    let (id, port) = target.and_then(|t| t.rsplit_once(':')).ok_or("target must be <sandboxId>:<port>")?;
    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    if port == 0 {
        return Err("invalid port");
    }
    let token = lines.find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim().eq_ignore_ascii_case("authorization").then(|| value.trim().strip_prefix("Bearer ").map(str::to_owned)).flatten()
    });
    Ok(Some((ConnectRequest { sandbox_id: id.to_owned(), port, token }, end + 4)))
}

pub struct Tunnel {
    pub manager: Arc<Manager>,
    pub token: Arc<String>,
    pub tls: Arc<rustls::ServerConfig>,
}

impl Tunnel {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let acceptor = tokio_rustls::TlsAcceptor::from(self.tls.clone());
        loop {
            let Ok((tcp, _)) = listener.accept().await else { continue };
            let this = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await else {
                    return;
                };
                let _ = this.handle(stream).await;
            });
        }
    }

    async fn handle<S>(&self, mut client: S) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = Vec::with_capacity(1024);
        let (req, head_len) = loop {
            let mut chunk = [0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(10), client.read(&mut chunk))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "slow request head"))??;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            match parse_connect(&buf) {
                Ok(Some(v)) => break v,
                Ok(None) => continue,
                Err(why) => return respond(&mut client, 400, why).await,
            }
        };
        let authorized = req.token.as_deref().is_some_and(|t| tokens_equal(t.as_bytes(), self.token.as_bytes()));
        if !authorized {
            return respond(&mut client, 401, "invalid host token").await;
        }
        let target = match self.manager.tunnel_target(&req.sandbox_id, req.port) {
            Ok(t) => t,
            Err(e) => return respond(&mut client, e.status(), &e.to_string()).await,
        };
        let mut upstream = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target)).await {
            Ok(Ok(s)) => s,
            _ => return respond(&mut client, 502, "sandbox port is not accepting connections").await,
        };
        upstream.set_nodelay(true)?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        if buf.len() > head_len {
            upstream.write_all(&buf[head_len..]).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        Ok(())
    }
}

async fn respond<S: tokio::io::AsyncWrite + Unpin>(client: &mut S, status: u16, message: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "code": status, "message": message }).to_string();
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Bad Gateway",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(resp.as_bytes()).await?;
    client.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_requests() {
        let raw = b"CONNECT i7x2k9:49983 HTTP/1.1\r\nHost: i7x2k9:49983\r\nAuthorization: Bearer tok\r\n\r\nextra";
        let (req, len) = parse_connect(raw).unwrap().unwrap();
        assert_eq!(req, ConnectRequest { sandbox_id: "i7x2k9".into(), port: 49983, token: Some("tok".into()) });
        assert_eq!(&raw[len..], b"extra");
    }

    #[test]
    fn rejects_bad_requests() {
        assert_eq!(parse_connect(b"CONNECT abc HTTP/1.1\r\n").unwrap(), None, "incomplete head");
        assert!(parse_connect(b"GET / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect(b"CONNECT abc HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect(b"CONNECT abc:0 HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect(b"CONNECT abc:99999 HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect(&vec![b'a'; MAX_HEAD]).is_err());
        let (req, _) = parse_connect(b"CONNECT a:1 HTTP/1.1\r\n\r\n").unwrap().unwrap();
        assert_eq!(req.token, None);
    }
}
