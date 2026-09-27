//! Extraction of the server name (SNI) from a TLS ClientHello.
//!
//! The ClientHello may be split across several TLS records, and each record
//! across several TCP segments, so the parser works on whatever prefix of the
//! stream has arrived and asks for more until the whole handshake message is
//! present. It never allocates more than the message it is reassembling,
//! which is bounded by [`MAX_CLIENT_HELLO`].
//!
//! Anything the parser does not fully understand is an error; the gateway
//! then treats the connection as opaque and falls back to the IP check,
//! never to a name it half-parsed.

/// Largest ClientHello handshake message accepted. Real ones, including
/// post-quantum key shares and resumption tickets, are a few KiB.
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

const RECORD_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const MAX_RECORD_LEN: usize = 16 * 1024;
const EXT_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SniError {
    #[error("not a TLS handshake record")]
    NotHandshake,
    #[error("ClientHello larger than {MAX_CLIENT_HELLO} bytes")]
    TooLarge,
    #[error("malformed ClientHello: {0}")]
    Malformed(&'static str),
}

/// What a complete ClientHello told us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// The `host_name` from the server_name extension, as sent.
    pub server_name: Option<String>,
}

/// Parses the ClientHello at the start of `buf`.
///
/// Returns `Ok(None)` when more bytes are needed.
pub fn parse_client_hello(buf: &[u8]) -> Result<Option<ClientHello>, SniError> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    if first != RECORD_HANDSHAKE {
        return Err(SniError::NotHandshake);
    }
    let mut message = Vec::new();
    let mut rest = buf;
    loop {
        if rest.len() < 5 {
            return Ok(None);
        }
        if rest[0] != RECORD_HANDSHAKE {
            return Err(SniError::Malformed(
                "non-handshake record inside ClientHello",
            ));
        }
        if rest[1] != 0x03 {
            return Err(SniError::Malformed("unsupported record version"));
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if len == 0 || len > MAX_RECORD_LEN {
            return Err(SniError::Malformed("bad record length"));
        }
        if rest.len() < 5 + len {
            return Ok(None);
        }
        message.extend_from_slice(&rest[5..5 + len]);
        rest = &rest[5 + len..];

        if message.len() >= 4 {
            if message[0] != HANDSHAKE_CLIENT_HELLO {
                return Err(SniError::Malformed(
                    "first handshake message is not a ClientHello",
                ));
            }
            let body_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
            if body_len > MAX_CLIENT_HELLO {
                return Err(SniError::TooLarge);
            }
            if message.len() >= 4 + body_len {
                return parse_body(&message[4..4 + body_len]).map(Some);
            }
        }
        if message.len() > MAX_CLIENT_HELLO + 4 {
            return Err(SniError::TooLarge);
        }
    }
}

fn parse_body(body: &[u8]) -> Result<ClientHello, SniError> {
    let mut r = Reader(body);
    r.skip(2, "legacy_version")?;
    r.skip(32, "random")?;
    let session_id = r.u8_len_bytes("session_id")?;
    if session_id.len() > 32 {
        return Err(SniError::Malformed("session_id too long"));
    }
    let suites = r.u16_len_bytes("cipher_suites")?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(SniError::Malformed("cipher_suites"));
    }
    if r.u8_len_bytes("compression_methods")?.is_empty() {
        return Err(SniError::Malformed("compression_methods"));
    }
    if r.0.is_empty() {
        // Pre-TLS 1.2 hellos may omit extensions entirely.
        return Ok(ClientHello { server_name: None });
    }
    let mut exts = Reader(r.u16_len_bytes("extensions")?);
    if !r.0.is_empty() {
        return Err(SniError::Malformed("trailing bytes after extensions"));
    }

    let mut seen: Vec<u16> = Vec::new();
    let mut server_name = None;
    while !exts.0.is_empty() {
        let kind = exts.u16("extension type")?;
        let data = exts.u16_len_bytes("extension data")?;
        if seen.contains(&kind) {
            return Err(SniError::Malformed("duplicate extension"));
        }
        seen.push(kind);
        if kind == EXT_SERVER_NAME {
            server_name = parse_server_name(data)?;
        }
    }
    Ok(ClientHello { server_name })
}

fn parse_server_name(data: &[u8]) -> Result<Option<String>, SniError> {
    let mut outer = Reader(data);
    let mut list = Reader(outer.u16_len_bytes("server_name_list")?);
    if !outer.0.is_empty() {
        return Err(SniError::Malformed("trailing bytes in server_name"));
    }
    let mut host = None;
    while !list.0.is_empty() {
        let name_type = list.u8("name_type")?;
        let name = list.u16_len_bytes("host_name")?;
        if name_type != NAME_TYPE_HOST {
            continue;
        }
        if host.is_some() {
            return Err(SniError::Malformed("more than one host_name"));
        }
        if name.is_empty() || !name.iter().all(|b| b.is_ascii_graphic()) {
            return Err(SniError::Malformed("host_name is not printable ASCII"));
        }
        host = Some(String::from_utf8_lossy(name).into_owned());
    }
    Ok(host)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], SniError> {
        if self.0.len() < n {
            return Err(SniError::Malformed(what));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn skip(&mut self, n: usize, what: &'static str) -> Result<(), SniError> {
        self.take(n, what).map(|_| ())
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, SniError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, SniError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u8_len_bytes(&mut self, what: &'static str) -> Result<&'a [u8], SniError> {
        let n = self.u8(what)? as usize;
        self.take(n, what)
    }

    fn u16_len_bytes(&mut self, what: &'static str) -> Result<&'a [u8], SniError> {
        let n = self.u16(what)? as usize;
        self.take(n, what)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A real ClientHello, as rustls would send it.
    fn client_hello(server_name: &str) -> Vec<u8> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(server_name.to_owned()).unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Re-frames a single-record ClientHello into records of `chunk` bytes.
    fn fragment(hello: &[u8], chunk: usize) -> Vec<u8> {
        let payload = &hello[5..];
        let mut out = Vec::new();
        for part in payload.chunks(chunk) {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn extracts_sni_from_a_real_client_hello() {
        let hello = client_hello("api.example.com");
        let parsed = parse_client_hello(&hello).unwrap().unwrap();
        assert_eq!(parsed.server_name.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn asks_for_more_on_every_prefix() {
        let hello = client_hello("api.example.com");
        for cut in [0, 1, 4, 5, 6, 40, hello.len() - 1] {
            assert_eq!(parse_client_hello(&hello[..cut]), Ok(None), "cut at {cut}");
        }
    }

    #[test]
    fn reassembles_a_client_hello_fragmented_across_records() {
        let hello = client_hello("files.pythonhosted.org");
        for chunk in [1, 7, 100] {
            let fragmented = fragment(&hello, chunk);
            let parsed = parse_client_hello(&fragmented).unwrap().unwrap();
            assert_eq!(
                parsed.server_name.as_deref(),
                Some("files.pythonhosted.org")
            );
            // Every byte prefix of the fragmented stream is either incomplete
            // or the same answer; never an error.
            for cut in (0..fragmented.len()).step_by(97) {
                assert_eq!(parse_client_hello(&fragmented[..cut]), Ok(None));
            }
        }
    }

    #[test]
    fn ip_address_connections_have_no_sni() {
        let hello = client_hello("192.0.2.1");
        let parsed = parse_client_hello(&hello).unwrap().unwrap();
        assert_eq!(parsed.server_name, None);
    }

    #[test]
    fn rejects_non_tls_and_malformed_input() {
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\n"),
            Err(SniError::NotHandshake)
        );
        assert!(matches!(
            parse_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x00]),
            Err(SniError::Malformed(_))
        ));
        // Record claims more than 16 KiB.
        assert!(matches!(
            parse_client_hello(&[0x16, 0x03, 0x01, 0x48, 0x01]),
            Err(SniError::Malformed(_))
        ));
        // ServerHello instead of ClientHello.
        let mut hello = client_hello("a.example.com");
        hello[5] = 0x02;
        assert!(matches!(
            parse_client_hello(&hello),
            Err(SniError::Malformed(_))
        ));
        // Garbage body of the right length.
        let mut junk = vec![0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04];
        junk.extend_from_slice(&[0xff; 4]);
        assert!(matches!(
            parse_client_hello(&junk),
            Err(SniError::Malformed(_))
        ));
        // An alert record in the middle of a fragmented hello.
        let hello = fragment(&client_hello("a.example.com"), 50);
        let mut spliced = hello[..55].to_vec();
        spliced.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        assert!(matches!(
            parse_client_hello(&spliced),
            Err(SniError::Malformed(_))
        ));
    }

    #[test]
    fn never_panics_on_mutated_input() {
        let hello = fragment(&client_hello("mutate.example.com"), 300);
        for i in 0..hello.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut m = hello.clone();
                m[i] ^= flip;
                let _ = parse_client_hello(&m);
                let _ = parse_client_hello(&m[..i]);
            }
        }
    }

    #[test]
    fn rejects_oversized_hello_before_buffering_it() {
        // Handshake header announcing a 1 MiB ClientHello.
        let buf = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x10, 0x00, 0x00];
        assert_eq!(parse_client_hello(&buf), Err(SniError::TooLarge));
    }

    #[test]
    fn rejects_duplicate_server_names() {
        // Minimal hand-built hello with two host_name entries.
        let name = b"a.example.com";
        let mut entry = vec![NAME_TYPE_HOST];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);
        let mut list = Vec::new();
        list.extend_from_slice(&entry);
        list.extend_from_slice(&entry);
        let mut ext = (list.len() as u16).to_be_bytes().to_vec();
        ext.extend_from_slice(&list);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        let mut exts = Vec::new();
        exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![HANDSHAKE_CLIENT_HELLO, 0, 0, body.len() as u8];
        msg.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        assert!(matches!(
            parse_client_hello(&rec),
            Err(SniError::Malformed(_))
        ));
    }
}
