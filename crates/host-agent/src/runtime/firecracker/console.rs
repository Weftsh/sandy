//! Bounded capture of a VMM's standard output and error.
//!
//! Firecracker writes the guest's serial console and its own log to stdout.
//! The guest controls that stream, so it is kept in a fixed-size ring buffer
//! per VM (never in a file) and read continuously, so a full pipe never
//! stalls the VMM. Its tail is attached to errors.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinHandle;

/// Bytes of console output kept per VM.
pub const CONSOLE_CAPACITY: usize = 64 * 1024;
/// Bytes of console output quoted in an error message.
pub const ERROR_TAIL: usize = 2048;

pub struct ConsoleLog {
    ring: Mutex<VecDeque<u8>>,
    capacity: usize,
}

impl ConsoleLog {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        })
    }

    /// Appends output, discarding the oldest bytes beyond the capacity.
    pub fn push(&self, data: &[u8]) {
        let data = &data[data.len().saturating_sub(self.capacity)..];
        let mut ring = self.ring.lock().expect("console lock poisoned");
        let overflow = (ring.len() + data.len()).saturating_sub(self.capacity);
        ring.drain(..overflow);
        ring.extend(data);
    }

    /// The last `max` bytes as text: starting at a line boundary when one is
    /// near, without carriage returns or terminal control sequences.
    pub fn tail(&self, max: usize) -> String {
        let bytes: Vec<u8> = {
            let ring = self.ring.lock().expect("console lock poisoned");
            let skip = ring.len().saturating_sub(max);
            let truncated = skip > 0;
            let mut bytes: Vec<u8> = ring.iter().skip(skip).copied().collect();
            if truncated {
                // Drop a partial first line (or at least a partial character).
                let cut = match bytes.iter().take(256).position(|&b| b == b'\n') {
                    Some(nl) => nl + 1,
                    None => bytes.iter().take_while(|&&b| b & 0xC0 == 0x80).count(),
                };
                bytes.drain(..cut);
            }
            bytes
        };
        sanitize(&String::from_utf8_lossy(&bytes))
    }

    /// Copies `reader` into the buffer until end of file. Firecracker's
    /// stdout closes only when the VMM exits.
    pub fn capture<R>(self: &Arc<Self>, mut reader: R) -> JoinHandle<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let log = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => log.push(&buf[..n]),
                }
            }
        })
    }
}

/// Keeps printable text, newlines and tabs; drops `\r`, escape sequences and
/// other control characters.
fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                // CSI sequences: ESC [ parameters final-byte.
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for n in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_newest_bytes() {
        let log = ConsoleLog::new(16);
        log.push(b"0123456789");
        log.push(b"abcdefghij");
        assert_eq!(log.ring.lock().unwrap().len(), 16);
        assert_eq!(log.tail(100), "456789abcdefghij");
        // One write larger than the buffer keeps its own tail.
        log.push(&[b'x'; 40]);
        assert_eq!(log.tail(100), "x".repeat(16));
    }

    #[test]
    fn stays_bounded_under_a_flood() {
        let log = ConsoleLog::new(CONSOLE_CAPACITY);
        let chunk = [b'y'; 3000];
        for _ in 0..1000 {
            log.push(&chunk);
        }
        assert_eq!(log.ring.lock().unwrap().len(), CONSOLE_CAPACITY);
        assert!(log.tail(ERROR_TAIL).len() <= ERROR_TAIL);
    }

    #[test]
    fn tail_starts_at_a_line_and_strips_control_sequences() {
        let log = ConsoleLog::new(1024);
        log.push(b"[    0.000000] Linux version 6.18\r\n");
        log.push(b"\x1b[31mKernel panic\x1b[0m - not syncing\r\n");
        assert_eq!(
            log.tail(1024),
            "[    0.000000] Linux version 6.18\nKernel panic - not syncing"
        );
        assert_eq!(log.tail(40), "Kernel panic - not syncing");
    }

    #[test]
    fn tail_never_splits_characters() {
        let log = ConsoleLog::new(1024);
        log.push("ééééé".as_bytes());
        let t = log.tail(5);
        assert!(!t.contains('\u{fffd}'), "{t:?}");
        assert_eq!(t, "éé");
    }

    #[tokio::test]
    async fn captures_a_stream_until_eof() {
        let log = ConsoleLog::new(1024);
        let reader = std::io::Cursor::new(b"hello from the guest\n".to_vec());
        log.capture(reader).await.unwrap();
        assert_eq!(log.tail(100), "hello from the guest");
    }
}
