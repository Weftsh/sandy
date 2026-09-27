//! Recognising plain HTTP/1.x from a connection's first bytes, and parsing the
//! authority (Host) a request names.
//!
//! Recognition only decides which path a connection takes. Once a connection
//! is HTTP, hyper parses every request itself and each one is checked on its
//! own; see `proxy`.

use std::net::IpAddr;
use std::str::FromStr;

use weft_netpolicy::policy::normalize_hostname;

/// Largest request head the classifier waits for.
pub const MAX_HEAD: usize = 8 * 1024;

const MAX_METHOD_LEN: usize = 16;
const MAX_HEADERS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeadError {
    #[error("not an HTTP/1.x request")]
    NotHttp,
    #[error("request head exceeds {MAX_HEAD} bytes")]
    TooLarge,
    #[error("request has more than one Host header")]
    DuplicateHost,
}

/// Whether `buf` starts like an HTTP request line: a method token followed by
/// a space. `None` means not enough bytes to tell.
pub fn looks_like_http(buf: &[u8]) -> Option<bool> {
    for (i, &b) in buf.iter().enumerate().take(MAX_METHOD_LEN + 1) {
        if b == b' ' {
            return Some(i > 0);
        }
        if !(b.is_ascii_uppercase() || b == b'-') {
            return Some(false);
        }
    }
    if buf.len() > MAX_METHOD_LEN {
        Some(false)
    } else {
        None
    }
}

/// The parts of a request head the classifier needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    /// The Host header, or the authority of an absolute-form target.
    pub authority: Option<String>,
    /// Bytes the head occupies.
    pub len: usize,
}

/// Parses a complete HTTP/1.x request head. `Ok(None)` means more bytes are
/// needed.
pub fn parse_head(buf: &[u8]) -> Result<Option<RequestHead>, HeadError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let len = match req.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) if buf.len() >= MAX_HEAD => return Err(HeadError::TooLarge),
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => return Err(HeadError::TooLarge),
        Err(_) => return Err(HeadError::NotHttp),
    };
    if len > MAX_HEAD {
        return Err(HeadError::TooLarge);
    }
    if !matches!(req.version, Some(0 | 1)) {
        return Err(HeadError::NotHttp);
    }
    let mut hosts = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"));
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(HeadError::DuplicateHost);
    }
    let authority = match host {
        Some(h) => Some(String::from_utf8_lossy(h.value).trim().to_owned()),
        None => req
            .path
            .and_then(|p| http::Uri::from_str(p).ok())
            .and_then(|u| u.authority().map(|a| a.as_str().to_owned())),
    };
    Ok(Some(RequestHead {
        method: req.method.unwrap_or_default().to_owned(),
        authority,
        len,
    }))
}

/// A request's target host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetHost {
    /// A normalized (lowercase, no trailing dot) DNS name.
    Name(String),
    /// An IP address literal.
    Ip(IpAddr),
}

impl std::fmt::Display for TargetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Parses `host[:port]` as found in a Host header or an absolute URI.
/// Rejects user info, empty hosts and anything that is not a valid DNS name
/// or IP literal.
pub fn parse_authority(authority: &str) -> Option<(TargetHost, Option<u16>)> {
    if authority.contains('@') {
        return None;
    }
    let parsed = http::uri::Authority::from_str(authority).ok()?;
    let host = parsed.host();
    // Without user info the authority is exactly `host[:port]`.
    let port = match authority.get(host.len()..)? {
        "" => None,
        rest => {
            let digits = rest.strip_prefix(':')?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(digits.parse::<u16>().ok()?)
        }
    };
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some((TargetHost::Ip(ip), port));
    }
    if host.starts_with('[') {
        return None;
    }
    normalize_hostname(host).map(|n| (TargetHost::Name(n), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_request_lines() {
        assert_eq!(looks_like_http(b"GET / HTTP/1.1\r\n"), Some(true));
        assert_eq!(looks_like_http(b"M-SEARCH * HTTP/1.1"), Some(true));
        assert_eq!(looks_like_http(b"POS"), None);
        assert_eq!(looks_like_http(b""), None);
        assert_eq!(looks_like_http(b" GET"), Some(false));
        assert_eq!(looks_like_http(b"get / HTTP/1.1"), Some(false));
        assert_eq!(looks_like_http(b"\x16\x03\x01"), Some(false));
        assert_eq!(looks_like_http(b"SSH-2.0-OpenSSH"), Some(false));
        assert_eq!(looks_like_http(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ "), Some(false));
    }

    #[test]
    fn parses_heads_and_host() {
        let head = b"GET /x HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\nbody";
        let parsed = parse_head(head).unwrap().unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.authority.as_deref(), Some("Example.com:8080"));
        assert_eq!(parsed.len, head.len() - 4);

        let abs = b"GET http://a.example.com/x HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_head(abs).unwrap().unwrap().authority.as_deref(),
            Some("a.example.com")
        );
        let http10 = b"GET / HTTP/1.0\r\n\r\n";
        assert_eq!(parse_head(http10).unwrap().unwrap().authority, None);
    }

    #[test]
    fn partial_oversized_and_invalid_heads() {
        assert_eq!(parse_head(b"GET / HTTP/1.1\r\nHost: a"), Ok(None));
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        assert_eq!(parse_head(&big), Err(HeadError::TooLarge));
        assert_eq!(parse_head(b"SET key value\r\n"), Err(HeadError::NotHttp));
        assert_eq!(
            parse_head(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Err(HeadError::NotHttp)
        );
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n"),
            Err(HeadError::DuplicateHost)
        );
        let mut many = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HEADERS {
            many.extend_from_slice(format!("x{i}: y\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(parse_head(&many), Err(HeadError::TooLarge));
    }

    #[test]
    fn parses_authorities() {
        let name = |n: &str| TargetHost::Name(n.to_owned());
        assert_eq!(
            parse_authority("API.Example.com"),
            Some((name("api.example.com"), None))
        );
        assert_eq!(
            parse_authority("a.example.com:8443"),
            Some((name("a.example.com"), Some(8443)))
        );
        assert_eq!(
            parse_authority("a.example.com."),
            Some((name("a.example.com"), None))
        );
        assert_eq!(
            parse_authority("10.1.2.3:80"),
            Some((TargetHost::Ip("10.1.2.3".parse().unwrap()), Some(80)))
        );
        assert_eq!(
            parse_authority("[2606:4700::1111]:443"),
            Some((
                TargetHost::Ip("2606:4700::1111".parse().unwrap()),
                Some(443)
            ))
        );
        for bad in [
            "",
            "user@a.com",
            "a.com:",
            "a.com:99999",
            "exa mple.com",
            "[nope]",
            "a..com",
            "-a.com",
        ] {
            assert_eq!(parse_authority(bad), None, "{bad:?}");
        }
    }
}
