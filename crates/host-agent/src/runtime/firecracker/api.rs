//! Client for the Firecracker API, served over HTTP/1.1 on a Unix socket
//! inside the jail.
//!
//! Each call uses a fresh connection: calls are few per VM lifetime and a
//! connection cannot outlive a VMM that was killed underneath it. Firecracker
//! answers `204 No Content` on success and `{"fault_message": "..."}` on
//! failure.

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, HOST};
use http::{Method, Request};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

/// Firecracker's responses are tiny; anything bigger is not Firecracker.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{op}: connecting to {}: {source}", socket.display())]
    Connect {
        op: String,
        socket: PathBuf,
        source: std::io::Error,
    },
    #[error("{op}: {message}")]
    Transport { op: String, message: String },
    #[error("{op}: Firecracker returned HTTP {status}: {message}")]
    Fault {
        op: String,
        status: u16,
        message: String,
    },
    #[error("{op}: no response within {timeout:?}")]
    Timeout { op: String, timeout: Duration },
}

#[derive(Clone, Debug)]
pub struct ApiClient {
    socket: PathBuf,
    timeout: Duration,
}

impl ApiClient {
    /// `timeout` bounds ordinary calls; snapshot calls take their own.
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }

    pub async fn put(&self, path: &str, body: &impl Serialize) -> Result<(), ApiError> {
        self.put_within(path, body, self.timeout).await
    }

    pub async fn put_within(
        &self,
        path: &str,
        body: &impl Serialize,
        timeout: Duration,
    ) -> Result<(), ApiError> {
        self.call(Method::PUT, path, Some(to_json(body)), timeout)
            .await
            .map(drop)
    }

    /// PUT with a body that is already JSON (a custom CPU template file).
    pub async fn put_raw(&self, path: &str, json: Vec<u8>) -> Result<(), ApiError> {
        self.call(Method::PUT, path, Some(json), self.timeout)
            .await
            .map(drop)
    }

    pub async fn patch(&self, path: &str, body: &impl Serialize) -> Result<(), ApiError> {
        self.call(Method::PATCH, path, Some(to_json(body)), self.timeout)
            .await
            .map(drop)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<Bytes, ApiError> {
        let op = format!("{method} {path}");
        tracing::debug!(socket = %self.socket.display(), %op, "firecracker api");
        match tokio::time::timeout(timeout, self.exchange(&op, method, path, body)).await {
            Ok(result) => result,
            Err(_) => Err(ApiError::Timeout { op, timeout }),
        }
    }

    async fn exchange(
        &self,
        op: &str,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes, ApiError> {
        let transport = |message: String| ApiError::Transport {
            op: op.to_owned(),
            message,
        };
        let stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|source| ApiError::Connect {
                    op: op.to_owned(),
                    socket: self.socket.clone(),
                    source,
                })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| transport(e.to_string()))?;
        // Drives the connection; aborted if this call is dropped (timeout).
        let _conn = AbortOnDrop(tokio::spawn(async move {
            let _ = conn.await;
        }));

        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, "localhost")
            .header(ACCEPT, "application/json");
        if body.is_some() {
            req = req.header(CONTENT_TYPE, "application/json");
        }
        let req = req
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| transport(format!("building request: {e}")))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| transport(e.to_string()))?;
        let status = resp.status();
        let bytes = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| transport(format!("reading response: {e}")))?
            .to_bytes();
        if status.is_success() {
            return Ok(bytes);
        }
        Err(ApiError::Fault {
            op: op.to_owned(),
            status: status.as_u16(),
            message: fault_message(&bytes),
        })
    }
}

fn to_json(body: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(body).expect("request bodies are plain data")
}

/// Extracts `fault_message` from an error body, or quotes the body.
fn fault_message(body: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(m) = v.get("fault_message").and_then(|m| m.as_str()) {
            return m.to_owned();
        }
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.is_empty() {
        return "(empty response)".into();
    }
    text.chars().take(512).collect()
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A scripted stand-in for Firecracker's API server.

    use std::convert::Infallible;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixListener;

    #[derive(Clone, Debug, PartialEq)]
    pub struct Call {
        pub method: String,
        pub path: String,
        pub body: serde_json::Value,
    }

    /// `(method, path) -> (status, body)`; unlisted requests get 204.
    pub type Script = Vec<(&'static str, &'static str, u16, &'static str)>;

    pub struct FakeFirecracker {
        pub calls: Arc<Mutex<Vec<Call>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl FakeFirecracker {
        pub fn serve(socket: &Path, script: Script) -> Self {
            let listener = UnixListener::bind(socket).unwrap();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let script = Arc::new(script);
            let recorded = Arc::clone(&calls);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (calls, script) = (Arc::clone(&recorded), Arc::clone(&script));
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let (calls, script) = (Arc::clone(&calls), Arc::clone(&script));
                            async move {
                                let method = req.method().to_string();
                                let path = req.uri().path().to_owned();
                                let raw = req.into_body().collect().await.unwrap().to_bytes();
                                let body = if raw.is_empty() {
                                    serde_json::Value::Null
                                } else {
                                    serde_json::from_slice(&raw).expect("requests carry JSON")
                                };
                                calls.lock().unwrap().push(Call {
                                    method: method.clone(),
                                    path: path.clone(),
                                    body,
                                });
                                let (status, reply) = script
                                    .iter()
                                    .find(|(m, p, _, _)| *m == method && *p == path)
                                    .map(|(_, _, s, b)| (*s, *b))
                                    .unwrap_or((204, ""));
                                if status == 0 {
                                    // Never answer.
                                    std::future::pending::<()>().await;
                                }
                                let mut resp =
                                    Response::new(Full::new(Bytes::from_static(reply.as_bytes())));
                                *resp.status_mut() = StatusCode::from_u16(status).unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            Self { calls, task }
        }

        pub fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        pub fn paths(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .map(|c| format!("{} {}", c.method, c.path))
                .collect()
        }
    }

    impl Drop for FakeFirecracker {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeFirecracker;
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn client(dir: &Path) -> ApiClient {
        ApiClient::new(dir.join("api.sock"), Duration::from_secs(5))
    }

    #[tokio::test]
    async fn sends_json_and_accepts_no_content() {
        let dir = tempfile::tempdir().unwrap();
        let fc = FakeFirecracker::serve(&dir.path().join("api.sock"), vec![]);
        let api = client(dir.path());
        api.put(
            "/machine-config",
            &json!({"vcpu_count": 2, "mem_size_mib": 512}),
        )
        .await
        .unwrap();
        api.patch("/vm", &json!({"state": "Paused"})).await.unwrap();
        api.put_raw("/cpu-config", br#"{"cpuid_modifiers":[]}"#.to_vec())
            .await
            .unwrap();
        let calls = fc.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            (calls[0].method.as_str(), calls[0].path.as_str()),
            ("PUT", "/machine-config")
        );
        assert_eq!(calls[0].body, json!({"vcpu_count": 2, "mem_size_mib": 512}));
        assert_eq!(
            (calls[1].method.as_str(), calls[1].body["state"].as_str()),
            ("PATCH", Some("Paused"))
        );
        assert_eq!(calls[2].body, json!({"cpuid_modifiers": []}));
    }

    #[tokio::test]
    async fn surfaces_fault_messages() {
        let dir = tempfile::tempdir().unwrap();
        let _fc = FakeFirecracker::serve(
            &dir.path().join("api.sock"),
            vec![
                (
                    "PUT",
                    "/snapshot/load",
                    400,
                    r#"{"fault_message":"Cannot open the memory file: No such file"}"#,
                ),
                ("PUT", "/actions", 500, "not json at all"),
            ],
        );
        let api = client(dir.path());
        let err = api.put("/snapshot/load", &json!({})).await.unwrap_err();
        match &err {
            ApiError::Fault {
                op,
                status,
                message,
            } => {
                assert_eq!(op, "PUT /snapshot/load");
                assert_eq!(*status, 400);
                assert_eq!(message, "Cannot open the memory file: No such file");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(err.to_string().contains("HTTP 400"));
        let err = api.put("/actions", &json!({})).await.unwrap_err();
        assert!(
            matches!(err, ApiError::Fault { status: 500, ref message, .. } if message == "not json at all")
        );
    }

    #[tokio::test]
    async fn times_out_and_reports_missing_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let _fc = FakeFirecracker::serve(
            &dir.path().join("api.sock"),
            vec![("PUT", "/snapshot/create", 0, "")],
        );
        let api = client(dir.path());
        let err = api
            .put_within("/snapshot/create", &json!({}), Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Timeout { .. }), "{err:?}");

        let missing = ApiClient::new(dir.path().join("nope.sock"), Duration::from_secs(1));
        assert!(matches!(
            missing.put("/vm", &json!({})).await.unwrap_err(),
            ApiError::Connect { .. }
        ));
    }

    #[test]
    fn fault_message_fallbacks() {
        assert_eq!(fault_message(br#"{"fault_message":"bad"}"#), "bad");
        assert_eq!(fault_message(b""), "(empty response)");
        assert_eq!(fault_message(&[b'x'; 2000]).len(), 512);
    }
}
