//! The install's interception CA, used by the credential proxy to terminate
//! TLS from a sandbox for hosts that carry a credential rule.
//!
//! Sandboxes trust this CA (it is installed in the sandbox image's trust
//! store), so the gateway can present a leaf for the SNI host, read each
//! request, inject the credential and forward it upstream over a separately
//! verified TLS connection. Leaves are ECDSA P-256, valid for 24 hours, and
//! cached per host for half that, so a cached leaf always has at least 12
//! hours left.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::cache::TtlCache;

pub const LEAF_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
const LEAF_REUSE: Duration = Duration::from_secs(12 * 60 * 60);
/// Tolerates sandboxes whose clock runs slightly behind the gateway's.
const BACKDATE: Duration = Duration::from_secs(60 * 60);
const LEAF_CACHE_ENTRIES: usize = 1024;

/// JSON shape of the CA secret in Secrets Manager.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaSecret {
    cert_pem: String,
    key_pem: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("issuing a leaf certificate failed: {0}")]
    Issue(#[from] rcgen::Error),
    #[error("building the TLS server configuration failed: {0}")]
    Tls(#[from] rustls::Error),
}

pub struct InterceptionCa {
    issuer: Issuer<'static, KeyPair>,
    ca_cert: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
    leaves: TtlCache<String, Arc<ServerConfig>>,
}

impl InterceptionCa {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> anyhow::Result<Self> {
        let ca_cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .context("the CA certificate is not a PEM certificate")?;
        let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .context("the CA key is not a PEM private key")?;
        let key = KeyPair::try_from(&key_der).context("unsupported CA key")?;
        let issuer =
            Issuer::from_ca_cert_der(&ca_cert, key).context("parsing the CA certificate")?;
        let ca = Self {
            issuer,
            ca_cert,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            leaves: TtlCache::new(LEAF_CACHE_ENTRIES),
        };
        ca.self_check()
            .context("the CA key does not match the CA certificate")?;
        Ok(ca)
    }

    /// Parses the Secrets Manager form: `{"certPem": "...", "keyPem": "..."}`.
    pub fn from_secret_json(json: &str) -> anyhow::Result<Self> {
        let secret: CaSecret = serde_json::from_str(json)
            .map_err(|_| anyhow!("the CA secret must be a JSON object with certPem and keyPem"))?;
        Self::from_pem(&secret.cert_pem, &secret.key_pem)
    }

    pub fn ca_certificate(&self) -> &CertificateDer<'static> {
        &self.ca_cert
    }

    /// The TLS server configuration presenting a leaf for `host`. `host` must
    /// be a normalized DNS name that passed the policy check.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let key = host.to_owned();
        if let Some(cfg) = self.leaves.get(&key) {
            return Ok(cfg);
        }
        let (leaf, leaf_key) = self.issue(host, OffsetDateTime::now_utc())?;
        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf], PrivateKeyDer::Pkcs8(leaf_key))?;
        // The credential proxy speaks HTTP/1.1 only.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves.insert(key, cfg.clone(), LEAF_REUSE);
        Ok(cfg)
    }

    /// Issues a leaf for `host`, valid from an hour before `now` for 24 hours.
    pub fn issue(
        &self,
        host: &str,
        now: OffsetDateTime,
    ) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), rcgen::Error> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.not_before = now - BACKDATE;
        params.not_after = now + LEAF_VALIDITY;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok((
            cert.der().clone(),
            PrivatePkcs8KeyDer::from(key.serialize_der()),
        ))
    }

    /// Issues a throwaway leaf and verifies it against the CA certificate, so
    /// a key that does not belong to the certificate fails at startup rather
    /// than on the first intercepted connection.
    fn self_check(&self) -> anyhow::Result<()> {
        let host = "weft-ca-self-check.invalid";
        let (leaf, _) = self.issue(host, OffsetDateTime::now_utc())?;
        verify_leaf(
            &self.ca_cert,
            &leaf,
            host,
            UnixTime::now(),
            self.provider.clone(),
        )
    }
}

/// Verifies `leaf` for `host` with `ca` as the only trust anchor.
pub fn verify_leaf(
    ca: &CertificateDer<'_>,
    leaf: &CertificateDer<'_>,
    host: &str,
    now: UnixTime,
    provider: Arc<CryptoProvider>,
) -> anyhow::Result<()> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone().into_owned())?;
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
    let name = ServerName::try_from(host.to_owned())?;
    verifier.verify_server_cert(leaf, &[], &name, &[], now)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca() -> (String, String) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Weft test interception CA");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    #[test]
    fn issues_short_lived_leaves_that_verify_against_the_ca() {
        let (cert, key) = test_ca();
        let ca = InterceptionCa::from_pem(&cert, &key).unwrap();
        let now = OffsetDateTime::now_utc();
        let (leaf, _) = ca.issue("api.example.com", now).unwrap();
        let ca_der = ca.ca_certificate();

        verify_leaf(
            ca_der,
            &leaf,
            "api.example.com",
            UnixTime::now(),
            provider(),
        )
        .unwrap();
        assert!(verify_leaf(
            ca_der,
            &leaf,
            "other.example.com",
            UnixTime::now(),
            provider()
        )
        .is_err());
        let in_25h = UnixTime::since_unix_epoch(Duration::from_secs(
            (now.unix_timestamp() + 25 * 3600) as u64,
        ));
        assert!(
            verify_leaf(ca_der, &leaf, "api.example.com", in_25h, provider()).is_err(),
            "leaves expire after 24 hours"
        );
        let in_23h = UnixTime::since_unix_epoch(Duration::from_secs(
            (now.unix_timestamp() + 23 * 3600) as u64,
        ));
        verify_leaf(ca_der, &leaf, "api.example.com", in_23h, provider()).unwrap();
    }

    #[test]
    fn caches_server_configs_per_host_with_http11_alpn() {
        let (cert, key) = test_ca();
        let ca = InterceptionCa::from_pem(&cert, &key).unwrap();
        let a = ca.server_config("a.example.com").unwrap();
        let a2 = ca.server_config("a.example.com").unwrap();
        let b = ca.server_config("b.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &a2));
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn rejects_mismatched_or_malformed_ca_material() {
        let (cert, _) = test_ca();
        let (_, other_key) = test_ca();
        assert!(InterceptionCa::from_pem(&cert, &other_key).is_err());
        assert!(InterceptionCa::from_pem("not pem", &other_key).is_err());
        assert!(InterceptionCa::from_secret_json("{}").is_err());
        let (cert, key) = test_ca();
        let json = serde_json::json!({"certPem": cert, "keyPem": key}).to_string();
        assert!(InterceptionCa::from_secret_json(&json).is_ok());
    }
}
