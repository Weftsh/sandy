//! Deciding what a sandbox connection speaks from its first bytes.
//!
//! The bytes are read (not peeked at the socket) into a bounded buffer and
//! replayed to whichever path handles the connection. A client that sends
//! nothing within [`FIRST_BYTE_TIMEOUT`] is assumed to wait for the server to
//! speak first (SSH, SMTP, most databases), which makes it opaque.

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{timeout_at, Instant};

use crate::http_head::{self, looks_like_http, MAX_HEAD};
use crate::sni::{self, MAX_CLIENT_HELLO};

pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(3);
/// Time allowed, after the first byte, for a complete ClientHello or request head.
pub const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Records header plus a ClientHello of the maximum size.
const MAX_TLS_PREFIX: usize = MAX_CLIENT_HELLO + 64 * 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// A TLS ClientHello with this server name.
    Tls { server_name: String },
    /// A complete HTTP/1.x request head.
    Http,
    /// Anything else, including TLS without SNI and server-speaks-first.
    Opaque { why: OpaqueWhy },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueWhy {
    ServerSpeaksFirst,
    TlsWithoutSni,
    Unrecognised,
    /// Looked like TLS or HTTP but was malformed, oversized or too slow.
    Malformed,
}

/// Reads until the protocol is known. `buf` holds bytes already read (after
/// the PROXY header) and, on return, every byte read so far.
pub async fn classify<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
) -> std::io::Result<Protocol> {
    classify_with(stream, buf, FIRST_BYTE_TIMEOUT, CLASSIFY_TIMEOUT).await
}

pub async fn classify_with<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    first_byte: Duration,
    rest: Duration,
) -> std::io::Result<Protocol> {
    if buf.is_empty() {
        let deadline = Instant::now() + first_byte;
        match read_more(stream, buf, MAX_TLS_PREFIX, deadline).await? {
            Read::Data => {}
            Read::Eof | Read::TimedOut => {
                return Ok(Protocol::Opaque {
                    why: OpaqueWhy::ServerSpeaksFirst,
                })
            }
        }
    }
    let deadline = Instant::now() + rest;

    if buf[0] == 0x16 {
        loop {
            match sni::parse_client_hello(buf) {
                Ok(Some(hello)) => {
                    return Ok(match hello.server_name {
                        // IP literals are not valid SNI; treat them like no SNI.
                        Some(name) if name.parse::<std::net::IpAddr>().is_err() => {
                            Protocol::Tls { server_name: name }
                        }
                        _ => Protocol::Opaque {
                            why: OpaqueWhy::TlsWithoutSni,
                        },
                    });
                }
                Ok(None) if buf.len() < MAX_TLS_PREFIX => {}
                Ok(None) | Err(_) => {
                    return Ok(Protocol::Opaque {
                        why: OpaqueWhy::Malformed,
                    })
                }
            }
            if read_more(stream, buf, MAX_TLS_PREFIX, deadline).await? != Read::Data {
                return Ok(Protocol::Opaque {
                    why: OpaqueWhy::Malformed,
                });
            }
        }
    }

    loop {
        match looks_like_http(buf) {
            Some(false) => {
                return Ok(Protocol::Opaque {
                    why: OpaqueWhy::Unrecognised,
                })
            }
            Some(true) => match http_head::parse_head(buf) {
                Ok(Some(_)) => return Ok(Protocol::Http),
                Ok(None) => {}
                Err(_) => {
                    return Ok(Protocol::Opaque {
                        why: OpaqueWhy::Malformed,
                    })
                }
            },
            None => {}
        }
        if read_more(stream, buf, MAX_HEAD, deadline).await? != Read::Data {
            return Ok(Protocol::Opaque {
                why: OpaqueWhy::Malformed,
            });
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Read {
    Data,
    Eof,
    TimedOut,
}

async fn read_more<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    limit: usize,
    deadline: Instant,
) -> std::io::Result<Read> {
    let room = limit.saturating_sub(buf.len());
    if room == 0 {
        return Ok(Read::Eof);
    }
    let mut chunk = vec![0u8; room.min(4096)];
    match timeout_at(deadline, stream.read(&mut chunk)).await {
        Err(_) => Ok(Read::TimedOut),
        Ok(Err(e)) => Err(e),
        Ok(Ok(0)) => Ok(Read::Eof),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(Read::Data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn run(chunks: Vec<&'static [u8]>, close: bool) -> (Protocol, usize) {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            for c in chunks {
                client.write_all(c).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            if !close {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        let mut buf = BytesMut::new();
        let p = classify_with(
            &mut server,
            &mut buf,
            Duration::from_millis(200),
            Duration::from_millis(300),
        )
        .await
        .unwrap();
        writer.abort();
        (p, buf.len())
    }

    #[tokio::test]
    async fn http_split_across_segments() {
        let (p, n) = run(
            vec![b"GE", b"T / HTTP/1.1\r\nHo", b"st: a.example.com\r\n\r\n"],
            false,
        )
        .await;
        assert_eq!(p, Protocol::Http);
        assert_eq!(n, 39);
    }

    #[tokio::test]
    async fn silent_clients_are_server_speaks_first() {
        let (p, _) = run(vec![], false).await;
        assert_eq!(
            p,
            Protocol::Opaque {
                why: OpaqueWhy::ServerSpeaksFirst
            }
        );
    }

    #[tokio::test]
    async fn unknown_and_stalled_protocols_are_opaque() {
        let (p, _) = run(vec![b"SSH-2.0-x\r\n"], false).await;
        assert_eq!(
            p,
            Protocol::Opaque {
                why: OpaqueWhy::Unrecognised
            }
        );
        // Looks like HTTP but never finishes its head.
        let (p, _) = run(vec![b"GET / HTTP/1.1\r\n"], false).await;
        assert_eq!(
            p,
            Protocol::Opaque {
                why: OpaqueWhy::Malformed
            }
        );
        // TLS record header, then EOF.
        let (p, _) = run(vec![b"\x16\x03\x01\x00\x10"], true).await;
        assert_eq!(
            p,
            Protocol::Opaque {
                why: OpaqueWhy::Malformed
            }
        );
    }
}
