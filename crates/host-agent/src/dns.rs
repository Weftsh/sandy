//! Guest resolver.
//!
//! Every DNS query a sandbox sends is redirected here. Names the sandbox's
//! egress policy allows are forwarded to the host's upstream resolver; every
//! other name gets NXDOMAIN without leaving the host, so a sandbox with no
//! allowlist cannot resolve anything and cannot tunnel data out through DNS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::slots::SlotTable;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_MESSAGE: usize = 4096;

pub struct Resolver {
    slots: Arc<SlotTable>,
    upstream: SocketAddr,
}

/// What to do with one query.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Forward,
    /// Respond with this message (NXDOMAIN or REFUSED).
    Answer(Vec<u8>),
    /// Drop: not a DNS query at all.
    Drop,
}

impl Resolver {
    pub fn new(slots: Arc<SlotTable>, upstream: SocketAddr) -> Self {
        Self { slots, upstream }
    }

    /// Decides how to handle `query` from `source`.
    pub fn decide(&self, source: IpAddr, query: &[u8]) -> Verdict {
        let Ok(msg) = Message::from_vec(query) else {
            return Verdict::Drop;
        };
        if msg.metadata.message_type != MessageType::Query {
            return Verdict::Drop;
        }
        let entry = match source {
            IpAddr::V4(v4) => self.slots.by_source(v4),
            IpAddr::V6(_) => None,
        };
        let Some(entry) = entry else {
            return Verdict::Answer(reply(&msg, ResponseCode::Refused));
        };
        // One question per query is all real resolvers send; refuse anything else.
        let allowed = msg.queries.len() == 1
            && msg
                .queries
                .iter()
                .all(|q| entry.policy.may_resolve(&q.name().to_ascii()));
        if allowed {
            Verdict::Forward
        } else {
            tracing::debug!(sandbox = %entry.sandbox_id, name = ?msg.queries.first().map(|q| q.name().to_ascii()), "dns denied");
            Verdict::Answer(reply(&msg, ResponseCode::NXDomain))
        }
    }

    pub async fn serve_udp(self: Arc<Self>, socket: UdpSocket) {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "dns recv failed");
                    continue;
                }
            };
            let query = buf[..n].to_vec();
            let this = self.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let response = match this.decide(peer.ip(), &query) {
                    Verdict::Drop => return,
                    Verdict::Answer(bytes) => bytes,
                    Verdict::Forward => match this.forward_udp(&query).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!(error = %e, "dns upstream failed");
                            match Message::from_vec(&query) {
                                Ok(m) => reply(&m, ResponseCode::ServFail),
                                Err(_) => return,
                            }
                        }
                    },
                };
                let _ = socket.send_to(&response, peer).await;
            });
        }
    }

    pub async fn serve_tcp(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _ =
                    tokio::time::timeout(Duration::from_secs(30), this.handle_tcp(stream, peer))
                        .await;
            });
        }
    }

    async fn handle_tcp(&self, mut stream: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        loop {
            let len = match stream.read_u16().await {
                Ok(l) => l as usize,
                Err(_) => return Ok(()),
            };
            if len == 0 || len > MAX_MESSAGE {
                return Ok(());
            }
            let mut query = vec![0u8; len];
            stream.read_exact(&mut query).await?;
            let response = match self.decide(peer.ip(), &query) {
                Verdict::Drop => return Ok(()),
                Verdict::Answer(bytes) => bytes,
                Verdict::Forward => self.forward_tcp(&query).await?,
            };
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await?;
        }
    }

    async fn forward_udp(&self, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let bind: SocketAddr = if self.upstream.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(self.upstream).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = tokio::time::timeout(UPSTREAM_TIMEOUT, sock.recv(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
        buf.truncate(n);
        // Only return a response that answers this query.
        if buf.len() < 2 || query.len() < 2 || buf[..2] != query[..2] {
            return Err(std::io::Error::other("mismatched upstream response"));
        }
        Ok(buf)
    }

    async fn forward_tcp(&self, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut s = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(self.upstream))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
        s.write_u16(query.len() as u16).await?;
        s.write_all(query).await?;
        let len = tokio::time::timeout(UPSTREAM_TIMEOUT, s.read_u16())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??
            as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

/// Builds a response with no answers and the given code.
fn reply(query: &Message, code: ResponseCode) -> Vec<u8> {
    let mut m = Message::error_msg(query.metadata.id, query.metadata.op_code, code);
    m.metadata.recursion_desired = query.metadata.recursion_desired;
    m.metadata.recursion_available = true;
    m.queries = query.queries.clone();
    m.to_vec().unwrap_or_default()
}

/// First `nameserver` in a resolv.conf, as a socket address on port 53.
pub fn upstream_from_resolv_conf(contents: &str) -> Option<SocketAddr> {
    contents.lines().find_map(|l| {
        let mut parts = l.split_whitespace();
        (parts.next() == Some("nameserver"))
            .then(|| parts.next())
            .flatten()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{NetConfig, Slot};
    use crate::slots::SlotEntry;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use weft_netpolicy::{CompiledPolicy, EgressPolicy};

    fn query(name: &str) -> Vec<u8> {
        let mut m = Message::new(4242, MessageType::Query, hickory_proto::op::OpCode::Query);
        m.metadata.recursion_desired = true;
        m.queries
            .push(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    fn setup() -> (Resolver, Slot) {
        let net = NetConfig {
            pool: "10.200.0.0/16".parse().unwrap(),
            dns_port: 1,
            egress_port: 2,
        };
        let slots = Arc::new(SlotTable::new(net, 4));
        let slot = slots.reserve().unwrap();
        let policy: EgressPolicy = serde_json::from_str(
            r#"{"allow":[{"host":"pypi.org"},{"host":"*.pythonhosted.org"}]}"#,
        )
        .unwrap();
        slots.occupy(
            slot.index,
            SlotEntry {
                sandbox_id: "sb".into(),
                policy: Arc::new(CompiledPolicy::compile(&policy).unwrap()),
            },
        );
        (Resolver::new(slots, "127.0.0.1:53".parse().unwrap()), slot)
    }

    fn rcode(bytes: &[u8]) -> ResponseCode {
        Message::from_vec(bytes).unwrap().metadata.response_code
    }

    #[test]
    fn forwards_allowed_names_only() {
        let (r, slot) = setup();
        let src = IpAddr::V4(slot.ns_ip);
        assert_eq!(r.decide(src, &query("pypi.org.")), Verdict::Forward);
        assert_eq!(
            r.decide(src, &query("files.pythonhosted.org.")),
            Verdict::Forward
        );
        match r.decide(src, &query("evil.example.")) {
            Verdict::Answer(b) => {
                assert_eq!(rcode(&b), ResponseCode::NXDomain);
                assert_eq!(Message::from_vec(&b).unwrap().metadata.id, 4242);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refuses_unknown_sources_and_drops_garbage() {
        let (r, slot) = setup();
        match r.decide(IpAddr::V4(slot.host_ip), &query("pypi.org.")) {
            Verdict::Answer(b) => assert_eq!(rcode(&b), ResponseCode::Refused),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            r.decide(IpAddr::V4(slot.ns_ip), b"\x00\x01garbage"),
            Verdict::Drop
        );
    }

    #[test]
    fn parses_resolv_conf() {
        assert_eq!(
            upstream_from_resolv_conf(
                "# c\nsearch x\nnameserver 169.254.169.253\nnameserver 8.8.8.8\n"
            ),
            Some("169.254.169.253:53".parse().unwrap())
        );
        assert_eq!(upstream_from_resolv_conf("search x\n"), None);
    }
}
