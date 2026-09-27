//! Egress forwarder.
//!
//! Every TCP connection a sandbox opens is redirected here by the host's
//! iptables rules. The forwarder recovers the original destination, works
//! out which sandbox opened it from the slot address, and hands the
//! connection to the egress gateway behind a PROXY v2 header. It makes no
//! allow/deny decision itself: the gateway applies the policy, so there is a
//! single enforcement point for connections.

use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use weft_netpolicy::ProxyHeader;

use crate::slots::SlotTable;

/// Most concurrent outbound connections one sandbox may hold open.
const MAX_CONNECTIONS_PER_SANDBOX: u32 = 512;

pub struct Forwarder {
    slots: Arc<SlotTable>,
    /// `host:port` of the egress gateway (a DNS name with several addresses
    /// is tried in order).
    gateway: String,
    open: dashmap_lite::Counters,
}

impl Forwarder {
    pub fn new(slots: Arc<SlotTable>, gateway: String) -> Self {
        Self { slots, gateway, open: dashmap_lite::Counters::default() }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "egress accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle(stream, peer).await {
                    tracing::debug!(%peer, error = %e, "egress connection closed");
                }
            });
        }
    }

    async fn handle(&self, mut client: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        let IpAddr::V4(peer_ip) = peer.ip() else {
            return Ok(());
        };
        let Some(entry) = self.slots.by_source(peer_ip) else {
            tracing::warn!(%peer, "egress connection from an address that is not an active sandbox");
            return Ok(());
        };
        let original = original_destination(&client)?;
        let guard = match self.open.acquire(&entry.sandbox_id, MAX_CONNECTIONS_PER_SANDBOX) {
            Some(g) => g,
            None => {
                tracing::warn!(sandbox = %entry.sandbox_id, "egress connection limit reached");
                return Ok(());
            }
        };
        let header = ProxyHeader {
            source: peer,
            destination: SocketAddr::V4(original),
            sandbox_id: entry.sandbox_id.clone(),
        }
        .encode()
        .map_err(std::io::Error::other)?;

        let mut upstream = self.connect_gateway().await?;
        upstream.set_nodelay(true)?;
        client.set_nodelay(true)?;
        upstream.write_all(&header).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        drop(guard);
        Ok(())
    }

    async fn connect_gateway(&self) -> std::io::Result<TcpStream> {
        let mut last = std::io::Error::other("egress gateway address did not resolve");
        for addr in tokio::net::lookup_host(&self.gateway).await? {
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = e,
                Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, "egress gateway connect timed out"),
            }
        }
        Err(last)
    }
}

/// The destination a redirected connection was originally addressed to.
fn original_destination(stream: &TcpStream) -> std::io::Result<SocketAddrV4> {
    let sa = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::OriginalDst).map_err(std::io::Error::from)?;
    Ok(SocketAddrV4::new(u32::from_be(sa.sin_addr.s_addr).into(), u16::from_be(sa.sin_port)))
}

/// Per-sandbox connection counters without an external concurrent map.
mod dashmap_lite {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct Counters {
        inner: Arc<Mutex<HashMap<String, Arc<AtomicU32>>>>,
    }

    pub struct Guard {
        counter: Arc<AtomicU32>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.counter.fetch_sub(1, Ordering::AcqRel);
        }
    }

    impl Counters {
        pub fn acquire(&self, key: &str, limit: u32) -> Option<Guard> {
            let counter = {
                let mut map = self.inner.lock().expect("poisoned");
                map.retain(|_, c| c.load(Ordering::Acquire) > 0 || Arc::strong_count(c) > 1);
                map.entry(key.to_owned()).or_default().clone()
            };
            let prev = counter.fetch_add(1, Ordering::AcqRel);
            if prev >= limit {
                counter.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            Some(Guard { counter })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn enforces_limits_and_releases_on_drop() {
            let c = Counters::default();
            let a = c.acquire("s", 2).unwrap();
            let _b = c.acquire("s", 2).unwrap();
            assert!(c.acquire("s", 2).is_none());
            assert!(c.acquire("other", 2).is_some());
            drop(a);
            assert!(c.acquire("s", 2).is_some());
        }
    }
}
