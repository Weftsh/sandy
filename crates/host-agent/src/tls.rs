//! TLS for the host agent's listeners.
//!
//! Each agent generates a fresh key pair and self-signed certificate at
//! start and registers the certificate with the control plane through its
//! IAM-authenticated heartbeat. The control plane and edge proxy pin that
//! certificate, so no private CA is needed and a host cannot impersonate
//! another host.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct HostIdentity {
    pub cert_pem: String,
    pub server_config: Arc<rustls::ServerConfig>,
}

pub fn generate(private_ip: &str) -> anyhow::Result<HostIdentity> {
    let mut params = rcgen::CertificateParams::new(vec!["weft-host-agent".to_owned()])?;
    if let Ok(ip) = private_ip.parse::<std::net::IpAddr>() {
        params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
    }
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "weft-host-agent");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(365);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(vec![der], key_der)?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(HostIdentity {
        cert_pem,
        server_config: Arc::new(server_config),
    })
}

/// Constant-time comparison for bearer tokens.
pub fn tokens_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A random URL-safe token with 256 bits of entropy.
pub fn random_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_identity() {
        let id = generate("10.0.1.23").unwrap();
        assert!(id.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(id.server_config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn compares_tokens() {
        assert!(tokens_equal(b"abc", b"abc"));
        assert!(!tokens_equal(b"abc", b"abd"));
        assert!(!tokens_equal(b"abc", b"abcd"));
        let t = random_token();
        assert_eq!(t.len(), 43);
        assert_ne!(t, random_token());
    }
}
