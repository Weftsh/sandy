//! Assembling the gateway from its configuration and accepting connections.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use aws_config::{BehaviorVersion, Region};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use weft_awsauth::{AwsIamSigner, HeaderCache, InternalAuth};

use crate::audit::{self, reason, ConnRecord};
use crate::ca::InterceptionCa;
use crate::config::{AuthConfig, CaSource, Config, SecretsConfig};
use crate::control_plane::PolicyClient;
use crate::io::Stats;
use crate::limits::Limits;
use crate::secrets::{AwsSecretsManager, SecretSource, SecretStore, StaticSecrets};
use crate::upstream::{client_tls_config, Upstreams};

pub struct Gateway {
    pub(crate) policies: PolicyClient,
    pub(crate) secrets: SecretStore,
    pub(crate) ca: InterceptionCa,
    pub(crate) upstreams: Upstreams,
    pub(crate) limits: Arc<Limits>,
    pub(crate) idle_timeout: Duration,
}

impl Gateway {
    /// Builds the gateway: loads the interception CA, sets up the secret
    /// source and control-plane authentication. Fails fast on bad material.
    pub async fn from_config(config: &Config) -> anyhow::Result<Arc<Self>> {
        // Everything here builds its rustls configs with an explicit
        // provider; this covers libraries that use the process default.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let needs_aws = matches!(config.ca, CaSource::SecretsManager(_))
            || config.secrets == SecretsConfig::SecretsManager;
        let aws = if needs_aws {
            let mut loader = aws_config::defaults(BehaviorVersion::latest());
            if let Some(region) = &config.region {
                loader = loader.region(Region::new(region.clone()));
            }
            Some(loader.load().await)
        } else {
            None
        };
        let aws_secrets = aws.as_ref().map(|c| Arc::new(AwsSecretsManager::new(c)));

        let ca = match &config.ca {
            CaSource::Files { cert, key } => {
                let cert = std::fs::read_to_string(cert)
                    .with_context(|| format!("reading {}", cert.display()))?;
                let key = std::fs::read_to_string(key)
                    .with_context(|| format!("reading {}", key.display()))?;
                InterceptionCa::from_pem(&cert, &key)?
            }
            CaSource::SecretsManager(id) => {
                let source = aws_secrets.as_ref().context("AWS configuration missing")?;
                let secret = source
                    .fetch(id)
                    .await
                    .context("loading the interception CA")?;
                InterceptionCa::from_secret_json(secret.expose())?
            }
        };

        let secret_source: Arc<dyn SecretSource> = match &config.secrets {
            SecretsConfig::DevFile(path) => Arc::new(StaticSecrets::from_file(path)?),
            SecretsConfig::SecretsManager => aws_secrets.context("AWS configuration missing")?,
        };

        let auth = match &config.auth {
            AuthConfig::AwsIam { region, server_id } => {
                InternalAuth::AwsIam(AwsIamSigner::from_default_chain(region, server_id).await?)
            }
            AuthConfig::DevToken(token) => InternalAuth::DevToken(token.clone()),
        };

        let mut extra_roots = Vec::new();
        if let Some(path) = config
            .dev
            .as_ref()
            .and_then(|d| d.upstream_ca_file.as_ref())
        {
            for cert in CertificateDer::pem_file_iter(path)
                .with_context(|| format!("reading {}", path.display()))?
            {
                extra_roots.push(cert.with_context(|| format!("parsing {}", path.display()))?);
            }
        }

        Ok(Arc::new(Self {
            policies: PolicyClient::new(&config.control_plane_url, HeaderCache::new(auth))?,
            secrets: SecretStore::new(secret_source),
            ca,
            upstreams: Upstreams::new(
                config.connect_timeout,
                client_tls_config(&extra_roots)?,
                config.dev.as_ref().map(|d| d.routing.clone()),
            ),
            limits: Limits::new(config.max_connections, config.max_connections_per_sandbox),
            idle_timeout: config.idle_timeout,
        }))
    }

    /// Accepts connections until `shutdown` resolves.
    pub async fn serve(self: Arc<Self>, listener: TcpListener, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let accepted = tokio::select! {
                () = &mut shutdown => return,
                accepted = listener.accept() => accepted,
            };
            let (tcp, peer) = match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    // Typically EMFILE; back off instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Some(permit) = self.limits.try_global() else {
                reject_over_capacity(peer);
                continue;
            };
            let _ = tcp.set_nodelay(true);
            let gw = self.clone();
            tokio::spawn(async move {
                crate::conn::handle(gw, tcp, peer).await;
                drop(permit);
            });
        }
    }

    /// Waits for open connections to finish, up to `grace`.
    pub async fn drain(&self, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        while self.limits.open_connections() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn open_connections(&self) -> usize {
        self.limits.open_connections()
    }
}

fn reject_over_capacity(peer: SocketAddr) {
    let mut record = ConnRecord::new(peer);
    record.deny(reason::TOO_MANY_CONNECTIONS);
    audit::connection(&record, &Stats::new());
}
