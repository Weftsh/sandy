//! Client for the in-guest agent (E2B's envd, Apache-2.0).
//!
//! envd accepts every request until its first `/init`, so the host agent
//! initializes each sandbox before the control plane is told it is running,
//! and the edge proxy never forwards `/init` from clients.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Port envd listens on inside every guest.
pub const ENVD_PORT: u16 = 49983;

#[derive(Debug, thiserror::Error)]
pub enum EnvdError {
    #[error("envd did not become healthy within {0:?}")]
    NotReady(Duration),
    #[error("envd request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("envd returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("envd protocol error: {0}")]
    Protocol(String),
}

#[derive(Clone, Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InitRequest {
    pub access_token: String,
    pub env_vars: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_workdir: Option<String>,
    /// RFC 3339. Makes envd set the guest clock, which a restored snapshot
    /// needs. Must be `None` in the namespace runtime, where the "guest"
    /// shares the host's kernel clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<String>,
}

#[derive(Clone)]
pub struct EnvdClient {
    http: reqwest::Client,
}

impl Default for EnvdClient {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvdClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            // The guest is reached through its slot namespace; never through
            // a proxy configured in the host's environment.
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("static client configuration");
        Self { http }
    }

    /// Polls `GET /health` until envd answers or the deadline passes.
    pub async fn wait_healthy(&self, addr: SocketAddr, within: Duration) -> Result<(), EnvdError> {
        let deadline = Instant::now() + within;
        let url = format!("http://{addr}/health");
        loop {
            let ok = matches!(
                self.http.get(&url).timeout(Duration::from_secs(2)).send().await,
                Ok(resp) if resp.status().is_success()
            );
            if ok {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(EnvdError::NotReady(within));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Initializes envd. Returns the version envd reports.
    pub async fn init(&self, addr: SocketAddr, req: &InitRequest) -> Result<String, EnvdError> {
        let resp = self
            .http
            .post(format!("http://{addr}/init"))
            .header("X-Access-Token", &req.access_token)
            .json(req)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(EnvdError::Status { status: status.as_u16(), body: truncate(body) });
        }
        Ok(resp
            .headers()
            .get("x-envd-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0.1.0")
            .to_owned())
    }

    /// Runs `sh -c <command>` as `user` and returns its exit code, using
    /// envd's Connect `process.Process/Start` server stream.
    pub async fn run(
        &self,
        addr: SocketAddr,
        access_token: Option<&str>,
        user: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<i32, EnvdError> {
        let body = serde_json::json!({
            "process": { "cmd": "/bin/sh", "args": ["-c", command], "envs": {} }
        });
        let mut req = self
            .http
            .post(format!("http://{addr}/process.Process/Start"))
            .timeout(timeout)
            .header("Content-Type", "application/connect+json")
            .header("Connect-Protocol-Version", "1")
            .basic_auth(user, Some(""))
            .body(connect_envelope(&serde_json::to_vec(&body).expect("static json")));
        if let Some(token) = access_token {
            req = req.header("X-Access-Token", token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(EnvdError::Status {
                status: status.as_u16(),
                body: truncate(String::from_utf8_lossy(&bytes).into_owned()),
            });
        }
        parse_process_stream(&bytes)
    }
}

fn truncate(mut s: String) -> String {
    if s.len() > 512 {
        let mut cut = 512;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// Wraps one Connect streaming message: flags byte, big-endian length, data.
pub fn connect_envelope(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Reads the exit code from a complete `process.Process/Start` stream.
pub fn parse_process_stream(mut bytes: &[u8]) -> Result<i32, EnvdError> {
    let mut exit: Option<i32> = None;
    while !bytes.is_empty() {
        if bytes.len() < 5 {
            return Err(EnvdError::Protocol("truncated envelope".into()));
        }
        let flags = bytes[0];
        let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if bytes.len() < 5 + len {
            return Err(EnvdError::Protocol("envelope overruns body".into()));
        }
        let msg: serde_json::Value = serde_json::from_slice(&bytes[5..5 + len])
            .map_err(|e| EnvdError::Protocol(format!("bad message: {e}")))?;
        if flags & 0x02 != 0 {
            if let Some(err) = msg.get("error") {
                return Err(EnvdError::Protocol(format!("envd error: {err}")));
            }
        } else if let Some(end) = msg.pointer("/event/end") {
            // proto3 JSON omits exitCode when it is zero.
            exit = Some(end.get("exitCode").and_then(|c| c.as_i64()).unwrap_or(0) as i32);
        }
        bytes = &bytes[5 + len..];
    }
    exit.ok_or_else(|| EnvdError::Protocol("stream ended without an exit event".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(flags: u8, json: &str) -> Vec<u8> {
        let mut v = connect_envelope(json.as_bytes());
        v[0] = flags;
        v
    }

    #[test]
    fn parses_exit_codes() {
        let mut stream = frame(0, r#"{"event":{"start":{"pid":10}}}"#);
        stream.extend(frame(0, r#"{"event":{"data":{"stdout":"aGkK"}}}"#));
        stream.extend(frame(0, r#"{"event":{"end":{"exited":true,"status":"exit status 0"}}}"#));
        stream.extend(frame(2, "{}"));
        assert_eq!(parse_process_stream(&stream).unwrap(), 0);

        let mut failing = frame(0, r#"{"event":{"end":{"exitCode":3,"exited":true}}}"#);
        failing.extend(frame(2, "{}"));
        assert_eq!(parse_process_stream(&failing).unwrap(), 3);
    }

    #[test]
    fn surfaces_stream_errors() {
        let stream = frame(2, r#"{"error":{"code":"unauthenticated","message":"invalid username"}}"#);
        assert!(matches!(parse_process_stream(&stream), Err(EnvdError::Protocol(m)) if m.contains("unauthenticated")));
        assert!(parse_process_stream(&[0, 0, 0]).is_err());
        assert!(parse_process_stream(&frame(2, "{}")).is_err());
    }

    #[test]
    fn init_omits_unset_fields() {
        let req = InitRequest { access_token: "t".into(), ..Default::default() };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v, serde_json::json!({"accessToken":"t","envVars":{}}));
    }
}
