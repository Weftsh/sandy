//! PROXY protocol version 2 framing, as used between the host agent's egress
//! forwarder and the egress gateway.
//!
//! The host agent intercepts every TCP connection a sandbox opens, recovers
//! the original destination, and opens a connection to the gateway that starts
//! with a PROXY v2 header. The header carries the original destination and a
//! TLV with the sandbox ID. The gateway checks that the sandbox is assigned
//! to the host the connection came from before trusting the TLV.
//!
//! Specification: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The 12-byte signature every v2 header starts with.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Custom TLV type carrying the sandbox ID (PP2_TYPE_MIN_CUSTOM range).
pub const TLV_SANDBOX_ID: u8 = 0xE0;

/// Largest header the decoder accepts. Real headers from the host agent are
/// well under 128 bytes.
pub const MAX_HEADER_LEN: usize = 16 + 512;

const MAX_SANDBOX_ID_LEN: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProxyProtocolError {
    #[error("connection did not start with a PROXY v2 signature")]
    BadSignature,
    #[error("unsupported PROXY protocol version or command {0:#04x}")]
    UnsupportedCommand(u8),
    #[error(
        "unsupported address family/protocol {0:#04x}; only TCP over IPv4 or IPv6 is accepted"
    )]
    UnsupportedFamily(u8),
    #[error("PROXY header of {0} bytes exceeds the limit")]
    TooLong(usize),
    #[error("malformed PROXY header: {0}")]
    Malformed(&'static str),
    #[error("PROXY header has no sandbox ID TLV")]
    MissingSandboxId,
}

/// A decoded PROXY v2 header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyHeader {
    /// The sandbox's address as seen by the host.
    pub source: SocketAddr,
    /// Where the sandbox was trying to connect.
    pub destination: SocketAddr,
    /// The sandbox that opened the connection.
    pub sandbox_id: String,
}

impl ProxyHeader {
    /// Encodes the header. Source and destination must share an address family.
    pub fn encode(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        if self.sandbox_id.is_empty() || self.sandbox_id.len() > MAX_SANDBOX_ID_LEN {
            return Err(ProxyProtocolError::Malformed("sandbox ID length"));
        }
        let mut body = Vec::with_capacity(64);
        let family = match (self.source.ip(), self.destination.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                body.extend_from_slice(&s.octets());
                body.extend_from_slice(&d.octets());
                0x11
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                body.extend_from_slice(&s.octets());
                body.extend_from_slice(&d.octets());
                0x21
            }
            _ => return Err(ProxyProtocolError::Malformed("mixed address families")),
        };
        body.extend_from_slice(&self.source.port().to_be_bytes());
        body.extend_from_slice(&self.destination.port().to_be_bytes());
        body.push(TLV_SANDBOX_ID);
        body.extend_from_slice(&(self.sandbox_id.len() as u16).to_be_bytes());
        body.extend_from_slice(self.sandbox_id.as_bytes());

        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&SIGNATURE);
        out.push(0x21); // version 2, PROXY command
        out.push(family);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes a header from the start of `buf`.
    ///
    /// Returns `Ok(None)` when more bytes are needed, or the header and the
    /// number of bytes it occupied.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, ProxyProtocolError> {
        let sig_len = buf.len().min(SIGNATURE.len());
        if buf[..sig_len] != SIGNATURE[..sig_len] {
            return Err(ProxyProtocolError::BadSignature);
        }
        if buf.len() < 16 {
            return Ok(None);
        }
        let ver_cmd = buf[12];
        if ver_cmd != 0x21 {
            return Err(ProxyProtocolError::UnsupportedCommand(ver_cmd));
        }
        let family = buf[13];
        let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let total = 16 + len;
        if total > MAX_HEADER_LEN {
            return Err(ProxyProtocolError::TooLong(total));
        }
        if buf.len() < total {
            return Ok(None);
        }
        let body = &buf[16..total];
        let (source, destination, rest) = match family {
            0x11 => {
                if body.len() < 12 {
                    return Err(ProxyProtocolError::Malformed("short IPv4 address block"));
                }
                let s = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                let d = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
                let sp = u16::from_be_bytes([body[8], body[9]]);
                let dp = u16::from_be_bytes([body[10], body[11]]);
                (
                    SocketAddr::new(s.into(), sp),
                    SocketAddr::new(d.into(), dp),
                    &body[12..],
                )
            }
            0x21 => {
                if body.len() < 36 {
                    return Err(ProxyProtocolError::Malformed("short IPv6 address block"));
                }
                let mut s = [0u8; 16];
                let mut d = [0u8; 16];
                s.copy_from_slice(&body[0..16]);
                d.copy_from_slice(&body[16..32]);
                let sp = u16::from_be_bytes([body[32], body[33]]);
                let dp = u16::from_be_bytes([body[34], body[35]]);
                (
                    SocketAddr::new(Ipv6Addr::from(s).into(), sp),
                    SocketAddr::new(Ipv6Addr::from(d).into(), dp),
                    &body[36..],
                )
            }
            other => return Err(ProxyProtocolError::UnsupportedFamily(other)),
        };

        let mut sandbox_id = None;
        let mut tlvs = rest;
        while !tlvs.is_empty() {
            if tlvs.len() < 3 {
                return Err(ProxyProtocolError::Malformed("truncated TLV"));
            }
            let kind = tlvs[0];
            let tlen = u16::from_be_bytes([tlvs[1], tlvs[2]]) as usize;
            if tlvs.len() < 3 + tlen {
                return Err(ProxyProtocolError::Malformed("TLV overruns header"));
            }
            let value = &tlvs[3..3 + tlen];
            if kind == TLV_SANDBOX_ID {
                if sandbox_id.is_some() {
                    return Err(ProxyProtocolError::Malformed("duplicate sandbox ID TLV"));
                }
                if value.is_empty() || value.len() > MAX_SANDBOX_ID_LEN {
                    return Err(ProxyProtocolError::Malformed("sandbox ID length"));
                }
                let id = std::str::from_utf8(value)
                    .map_err(|_| ProxyProtocolError::Malformed("sandbox ID is not UTF-8"))?;
                if !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(ProxyProtocolError::Malformed(
                        "sandbox ID has invalid characters",
                    ));
                }
                sandbox_id = Some(id.to_owned());
            }
            tlvs = &tlvs[3 + tlen..];
        }
        let sandbox_id = sandbox_id.ok_or(ProxyProtocolError::MissingSandboxId)?;
        Ok(Some((
            Self {
                source,
                destination,
                sandbox_id,
            },
            total,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> ProxyHeader {
        ProxyHeader {
            source: "10.12.0.2:40000".parse().unwrap(),
            destination: "140.82.112.3:443".parse().unwrap(),
            sandbox_id: "i7x2k9q3m1".into(),
        }
    }

    #[test]
    fn round_trips_ipv4_and_ipv6() {
        let h = header();
        let bytes = h.encode().unwrap();
        let mut stream = bytes.clone();
        stream.extend_from_slice(b"\x16\x03\x01payload");
        let (decoded, used) = ProxyHeader::decode(&stream).unwrap().unwrap();
        assert_eq!(decoded, h);
        assert_eq!(used, bytes.len());
        assert_eq!(&stream[used..used + 3], b"\x16\x03\x01");

        let h6 = ProxyHeader {
            source: "[fd00::2]:1".parse().unwrap(),
            destination: "[2606:4700::1111]:443".parse().unwrap(),
            sandbox_id: "abc".into(),
        };
        let (d6, _) = ProxyHeader::decode(&h6.encode().unwrap()).unwrap().unwrap();
        assert_eq!(d6, h6);
    }

    #[test]
    fn partial_input_asks_for_more() {
        let bytes = header().encode().unwrap();
        for cut in [0, 5, 12, 15, 16, bytes.len() - 1] {
            assert_eq!(
                ProxyHeader::decode(&bytes[..cut]).unwrap(),
                None,
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn rejects_non_proxy_traffic_immediately() {
        assert_eq!(
            ProxyHeader::decode(b"GET / HTTP/1.1\r\n"),
            Err(ProxyProtocolError::BadSignature)
        );
        assert_eq!(
            ProxyHeader::decode(b"\x16"),
            Err(ProxyProtocolError::BadSignature)
        );
    }

    #[test]
    fn rejects_malformed_headers() {
        let mut bytes = header().encode().unwrap();
        bytes[12] = 0x20; // LOCAL command
        assert_eq!(
            ProxyHeader::decode(&bytes),
            Err(ProxyProtocolError::UnsupportedCommand(0x20))
        );

        let mut bytes = header().encode().unwrap();
        bytes[13] = 0x12; // UDP over IPv4
        assert_eq!(
            ProxyHeader::decode(&bytes),
            Err(ProxyProtocolError::UnsupportedFamily(0x12))
        );

        let mut bytes = header().encode().unwrap();
        bytes[14..16].copy_from_slice(&(4000u16).to_be_bytes());
        assert!(matches!(
            ProxyHeader::decode(&bytes),
            Err(ProxyProtocolError::TooLong(_))
        ));

        // Header without the sandbox TLV.
        let mut bytes = header().encode().unwrap();
        let tlv_len = 3 + "i7x2k9q3m1".len();
        bytes.truncate(bytes.len() - tlv_len);
        let new_len = (bytes.len() - 16) as u16;
        bytes[14..16].copy_from_slice(&new_len.to_be_bytes());
        assert_eq!(
            ProxyHeader::decode(&bytes),
            Err(ProxyProtocolError::MissingSandboxId)
        );
    }

    #[test]
    fn rejects_sandbox_ids_with_unsafe_characters() {
        let mut h = header();
        h.sandbox_id = "a/b".into();
        let bytes = h.encode().unwrap();
        assert!(matches!(
            ProxyHeader::decode(&bytes),
            Err(ProxyProtocolError::Malformed(_))
        ));
    }
}
