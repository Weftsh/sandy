//! Stream plumbing: replaying bytes read while classifying a connection,
//! counting bytes for the audit log, the idle timeout, and task ownership.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Byte counters and last-activity time for one sandbox connection.
#[derive(Debug)]
pub struct Stats {
    started: Instant,
    /// Bytes read from the sandbox.
    up: AtomicU64,
    /// Bytes written to the sandbox.
    down: AtomicU64,
    last_activity_ms: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Excludes bytes that belong to the gateway's own framing, such as the
    /// PROXY header.
    pub fn discount_up(&self, n: u64) {
        self.up.fetch_sub(n.min(self.bytes_up()), Ordering::Relaxed);
    }

    fn touch(&self) {
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_activity_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_activity_ms.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves once no byte has moved in either direction for `idle`.
///
/// Every byte of every protocol path passes through the sandbox-side stream,
/// so watching that stream alone covers uploads and downloads.
pub async fn idle_watchdog(stats: &Stats, idle: Duration) {
    loop {
        let quiet = stats.idle_for();
        if quiet >= idle {
            return;
        }
        tokio::time::sleep(idle - quiet).await;
    }
}

/// Counts bytes and records activity on the sandbox-side stream.
#[derive(Debug)]
pub struct Metered<S> {
    inner: S,
    stats: Arc<Stats>,
}

impl<S> Metered<S> {
    pub fn new(inner: S, stats: Arc<Stats>) -> Self {
        Self { inner, stats }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.stats.up.fetch_add(n as u64, Ordering::Relaxed);
            self.stats.touch();
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.stats.down.fetch_add(*n as u64, Ordering::Relaxed);
                self.stats.touch();
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A stream that first yields bytes already read from it.
#[derive(Debug)]
pub struct Rewind<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Rewind<S> {
    pub fn new(inner: S, prefix: Bytes) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Aborts a spawned task when dropped, so helper tasks such as an upstream
/// HTTP connection never outlive the sandbox connection that owns them.
#[derive(Debug)]
pub struct AbortOnDrop<T>(pub JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn rewind_replays_prefix_then_reads_inner() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b" world").await.unwrap();
        drop(a);
        let mut r = Rewind::new(b, Bytes::from_static(b"hello"));
        let mut out = String::new();
        r.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test]
    async fn metered_counts_both_directions() {
        let (mut peer, ours) = tokio::io::duplex(64);
        let stats = Arc::new(Stats::new());
        let mut m = Metered::new(ours, stats.clone());
        peer.write_all(b"12345").await.unwrap();
        let mut buf = [0u8; 5];
        m.read_exact(&mut buf).await.unwrap();
        m.write_all(b"abc").await.unwrap();
        assert_eq!((stats.bytes_up(), stats.bytes_down()), (5, 3));
        stats.discount_up(2);
        assert_eq!(stats.bytes_up(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watchdog_fires_only_after_quiet_period() {
        let stats = Stats::new();
        let fired = tokio::time::timeout(
            Duration::from_secs(5),
            idle_watchdog(&stats, Duration::from_secs(10)),
        )
        .await;
        assert!(fired.is_err());
        let fired = tokio::time::timeout(
            Duration::from_secs(6),
            idle_watchdog(&stats, Duration::from_secs(10)),
        )
        .await;
        assert!(fired.is_ok());
    }
}
