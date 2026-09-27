//! Registration and heartbeat.
//!
//! The host announces itself to the control plane every few seconds with
//! its address, certificate, token, capacity and the sandboxes it runs. The
//! call is authenticated with the host's IAM role (see `weft-awsauth`), so
//! only instances launched with the host role can register, and each can
//! register only as itself.

use std::sync::Arc;
use std::time::Duration;

use weft_awsauth::{HeaderCache, AUTH_HEADER};

use crate::api_types::{Capacity, HeartbeatRequest, HeartbeatResponse, HeartbeatSandbox};
use crate::manager::Manager;

pub struct Registration {
    pub control_plane_url: String,
    pub auth: Arc<HeaderCache>,
    pub host_id: String,
    pub private_ip: String,
    pub api_port: u16,
    pub tunnel_port: u16,
    pub cert_pem: String,
    pub token: Arc<String>,
    pub capacity: Capacity,
    pub version: &'static str,
}

impl Registration {
    pub async fn run(self, manager: Arc<Manager>) {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("static client configuration");
        let url = format!("{}/internal/v1/hosts/heartbeat", self.control_plane_url.trim_end_matches('/'));
        let mut interval = Duration::from_secs(5);
        let mut failures = 0u32;
        loop {
            match self.beat(&http, &url, &manager).await {
                Ok(resp) => {
                    if failures > 0 {
                        tracing::info!("control plane heartbeat recovered");
                    }
                    failures = 0;
                    interval = Duration::from_secs(resp.heartbeat_interval_sec.clamp(1, 60));
                }
                Err(e) => {
                    failures += 1;
                    if failures == 1 || failures % 12 == 0 {
                        tracing::warn!(error = %e, failures, "control plane heartbeat failed");
                    }
                    if failures == 1 {
                        self.auth.invalidate().await;
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn beat(&self, http: &reqwest::Client, url: &str, manager: &Manager) -> anyhow::Result<HeartbeatResponse> {
        let body = HeartbeatRequest {
            host_id: self.host_id.clone(),
            private_ip: self.private_ip.clone(),
            api_port: self.api_port,
            tunnel_port: self.tunnel_port,
            cert_pem: self.cert_pem.clone(),
            token: self.token.as_str().to_owned(),
            version: self.version.to_owned(),
            runtime: manager.runtime_name().to_owned(),
            capacity: self.capacity.clone(),
            sandboxes: manager
                .list()
                .into_iter()
                .map(|s| HeartbeatSandbox { sandbox_id: s.sandbox_id, state: s.state })
                .collect(),
            templates: manager.cached_templates(),
            draining: false,
        };
        let header = self.auth.header().await?;
        let resp = http.post(url).header(AUTH_HEADER, header.as_ref()).json(&body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {status}: {}", text.chars().take(300).collect::<String>());
        }
        Ok(resp.json().await?)
    }
}
