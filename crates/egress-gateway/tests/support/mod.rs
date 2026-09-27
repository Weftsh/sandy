//! In-process test environment: a mock control plane, local upstream
//! servers, a gateway started with development seams, and log capture.
//!
//! All key material is generated at test time. Nothing touches the network
//! beyond loopback.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use http::{header, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use weft_egress_gateway::{Args, Config, Gateway};
use weft_netpolicy::ProxyHeader;

pub const DEV_TOKEN: &str = "test-token";
pub const SECRET_ID: &str = "test/api-key";
pub const BANNER: &[u8] = b"SSH-2.0-weft-test\r\n";
/// Original destination used for name-based traffic; never dialled.
pub const NAMED_DST_IP: &str = "10.99.0.1";
/// Original destination the dev redirect sends to the banner server.
pub const DB_DST: &str = "10.99.0.7:2222";

// ---------------------------------------------------------------- logging

static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Captures every log line of this test binary, at every level, as JSON.
pub fn init_logging() {
    LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(Capture(buf.clone()))
            .init();
        buf
    });
}

pub fn logs() -> String {
    let buf = LOGS.get().expect("init_logging not called");
    String::from_utf8_lossy(&buf.lock().unwrap()).into_owned()
}

/// Audit lines of one sandbox and event kind.
pub fn audit_lines(sandbox_id: &str, event: &str) -> Vec<Value> {
    logs()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["target"] == "audit" && v["event"] == event && v["sandboxId"] == sandbox_id)
        .collect()
}

/// Waits for the connection audit line(s) of a sandbox to appear.
pub async fn wait_for_connections(sandbox_id: &str, count: usize) -> Vec<Value> {
    for _ in 0..100 {
        let lines = audit_lines(sandbox_id, "connection");
        if lines.len() >= count {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no audit line for {sandbox_id}; logs:\n{}", logs());
}

// ---------------------------------------------------------------- PKI

pub struct TestCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    pub fn new(name: &str) -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        let key_pem = key.serialize_pem();
        Self {
            cert_pem: cert.pem(),
            key_pem,
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    pub fn leaf(&self, names: &[&str]) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params =
            CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

pub fn client_config(root: &CertificateDer<'static>, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

pub async fn tls_connect(
    stream: TcpStream,
    sni: &str,
    root: &CertificateDer<'static>,
    alpn: &[&[u8]],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(client_config(root, alpn));
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
        .await
        .map_err(|_| std::io::Error::other("TLS handshake timed out"))?
}

// ---------------------------------------------------------------- servers

/// Answers every request with JSON describing what it received; switches
/// `Upgrade: echo` requests to a raw echo.
async fn echo(mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|v| v == "echo")
    {
        let on = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            if let Ok(upgraded) = on.await {
                let (mut r, mut w) = tokio::io::split(TokioIo::new(upgraded));
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut()
            .insert(header::CONNECTION, "upgrade".parse().unwrap());
        resp.headers_mut()
            .insert(header::UPGRADE, "echo".parse().unwrap());
        return Ok(resp);
    }
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in req.headers() {
        headers
            .entry(k.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(v.as_bytes()).into_owned());
    }
    let method = req.method().to_string();
    let path = req.uri().to_string();
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let doc = json!({"method": method, "path": path, "headers": headers, "bodyLen": body.len()});
    let mut resp = Response::new(Full::new(Bytes::from(doc.to_string())));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    Ok(resp)
}

async fn serve_http<S>(io: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service_fn(echo))
        .with_upgrades()
        .await;
}

async fn start_plain_http() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve_http(tcp));
        }
    });
    addr
}

async fn start_tls_http(ca: &TestCa, names: &[&str]) -> SocketAddr {
    let (chain, key) = ca.leaf(names);
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_http(tls).await;
                }
            });
        }
    });
    addr
}

/// A server-speaks-first service: sends a banner, then echoes.
async fn start_banner(accepted: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if tcp.write_all(BANNER).await.is_ok() {
                    let (mut r, mut w) = tcp.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
        }
    });
    addr
}

/// The control plane's internal egress endpoint, backed by a fixed map.
async fn start_control_plane(
    sandboxes: HashMap<String, Value>,
    hits: Arc<AtomicUsize>,
) -> SocketAddr {
    let sandboxes = Arc::new(sandboxes);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let sandboxes = sandboxes.clone();
            let hits = hits.clone();
            let svc = service_fn(move |req: Request<Incoming>| {
                let sandboxes = sandboxes.clone();
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let auth_ok = req
                        .headers()
                        .get("x-weft-internal-auth")
                        .is_some_and(|v| v == format!("dev-token {DEV_TOKEN}").as_str());
                    let path = req.uri().path().to_owned();
                    let id = path
                        .strip_prefix("/internal/v1/sandboxes/")
                        .and_then(|p| p.strip_suffix("/egress"));
                    let (status, body) = match (auth_ok, id.and_then(|id| sandboxes.get(id))) {
                        (false, _) => (StatusCode::UNAUTHORIZED, String::new()),
                        (true, Some(doc)) => (StatusCode::OK, doc.to_string()),
                        (true, None) => (StatusCode::NOT_FOUND, String::new()),
                    };
                    let mut resp = Response::new(Full::new(Bytes::from(body)));
                    *resp.status_mut() = status;
                    Ok::<_, Infallible>(resp)
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    addr
}

// ---------------------------------------------------------------- env

pub struct Env {
    pub gateway: SocketAddr,
    pub gateway_handle: Arc<Gateway>,
    pub interception_ca: TestCa,
    pub upstream_ca: TestCa,
    pub secret_value: String,
    pub control_plane_hits: Arc<AtomicUsize>,
    pub banner_accepts: Arc<AtomicUsize>,
    pub banner_addr: SocketAddr,
    suffix: String,
    _dir: tempfile::TempDir,
}

fn random_hex() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    );
    format!("{:016x}", h.finish())
}

impl Env {
    pub async fn start() -> Self {
        Self::start_with(&[]).await
    }

    /// Starts everything; `extra` is appended to the gateway's command line.
    pub async fn start_with(extra: &[&str]) -> Self {
        init_logging();
        let suffix = random_hex();
        let secret_value = format!("sk-test-{}", random_hex());
        let interception_ca = TestCa::new("Weft test interception CA");
        let upstream_ca = TestCa::new("Weft test upstream CA");

        let names = ["pass.example.com", "creds.example.com", "other.example.com"];
        let tls_addr = start_tls_http(&upstream_ca, &names).await;
        let http_addr = start_plain_http().await;
        let banner_accepts = Arc::new(AtomicUsize::new(0));
        let banner_addr = start_banner(banner_accepts.clone()).await;

        let id = |name: &str| format!("{name}-{suffix}");
        let local = |policy: Value| json!({"hostIp": "127.0.0.1", "policy": policy});
        let credential = json!({
            "host": "creds.example.com",
            "header": "Authorization",
            "secretId": SECRET_ID,
            "secretKey": "apiKey",
            "format": "Bearer {{secret}}"
        });
        let mut sandboxes: HashMap<String, Value> = [
            ("empty", local(json!({}))),
            (
                "web",
                local(json!({"allow": [
                    {"host": "pass.example.com"},
                    {"host": "plain.example.com"},
                    {"host": "other.example.com"}
                ]})),
            ),
            (
                "creds",
                local(
                    json!({"allow": [{"host": "other.example.com"}], "credentials": [credential]}),
                ),
            ),
            ("star", local(json!({"allow": [{"host": "*"}]}))),
            (
                "db",
                local(json!({"allow": [{"host": "10.99.0.0/16", "ports": [2222]}]})),
            ),
            (
                "elsewhere",
                json!({"hostIp": "10.0.1.23", "policy": {"allow": [{"host": "*"}]}}),
            ),
            ("invalid", local(json!({"allow": [{"host": "*.com"}]}))),
            (
                "nosecret",
                local(json!({"credentials": [{
                    "host": "pass.example.com",
                    "header": "x-api-key",
                    "secretId": "does/not/exist"
                }]})),
            ),
        ]
        .into_iter()
        .map(|(name, mut doc)| {
            doc["sandboxId"] = json!(id(name));
            (id(name), doc)
        })
        .collect();
        // A response for the wrong sandbox must never be accepted.
        sandboxes.insert(
            id("confused"),
            json!({"sandboxId": id("web"), "hostIp": "127.0.0.1", "policy": {}}),
        );

        let control_plane_hits = Arc::new(AtomicUsize::new(0));
        let cp = start_control_plane(sandboxes, control_plane_hits.clone()).await;

        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        std::fs::write(path("ca.pem"), &interception_ca.cert_pem).unwrap();
        std::fs::write(path("ca.key"), &interception_ca.key_pem).unwrap();
        std::fs::write(path("upstream-ca.pem"), &upstream_ca.cert_pem).unwrap();
        let secret_json = json!({"apiKey": secret_value}).to_string();
        let secrets = HashMap::from([(SECRET_ID, secret_json)]);
        std::fs::write(
            path("secrets.json"),
            serde_json::to_string(&secrets).unwrap(),
        )
        .unwrap();

        let mut argv: Vec<String> = [
            "weft-egress-gateway",
            "--listen",
            "127.0.0.1:0",
            "--control-plane-url",
            &format!("http://{cp}"),
            "--dev",
            "--dev-token",
            DEV_TOKEN,
            "--ca-cert-file",
            &path("ca.pem"),
            "--ca-key-file",
            &path("ca.key"),
            "--dev-secrets-file",
            &path("secrets.json"),
            "--dev-upstream-ca-file",
            &path("upstream-ca.pem"),
            "--dev-resolve",
            &format!("pass.example.com={tls_addr}"),
            "--dev-resolve",
            &format!("creds.example.com={tls_addr}"),
            "--dev-resolve",
            &format!("plain.example.com={http_addr}"),
            "--dev-resolve",
            &format!("other.example.com={http_addr}"),
            "--dev-redirect",
            &format!("{DB_DST}={banner_addr}"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        argv.extend(extra.iter().map(|s| s.to_string()));
        let config = Config::from_args(Args::try_parse_from(argv).unwrap()).unwrap();
        let gateway = Gateway::from_config(&config).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(gateway.clone().serve(listener, std::future::pending()));

        Self {
            gateway: addr,
            gateway_handle: gateway,
            interception_ca,
            upstream_ca,
            secret_value,
            control_plane_hits,
            banner_accepts,
            banner_addr,
            suffix,
            _dir: dir,
        }
    }

    /// The full sandbox ID for a sandbox name in this environment.
    pub fn id(&self, name: &str) -> String {
        format!("{name}-{}", self.suffix)
    }

    /// Opens a connection to the gateway as the host agent would.
    pub async fn connect(&self, sandbox: &str, destination: &str) -> TcpStream {
        let mut tcp = TcpStream::connect(self.gateway).await.unwrap();
        let header = ProxyHeader {
            source: "10.200.0.2:40000".parse().unwrap(),
            destination: destination.parse().unwrap(),
            sandbox_id: self.id(sandbox),
        };
        tcp.write_all(&header.encode().unwrap()).await.unwrap();
        tcp
    }

    pub fn named_dst(port: u16) -> String {
        format!("{NAMED_DST_IP}:{port}")
    }
}

// ---------------------------------------------------------------- clients

pub async fn http_client<S>(io: S) -> SendRequest<Full<Bytes>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    sender
}

pub fn get(host: &str, path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .header(header::HOST, host)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

pub struct Answer {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl Answer {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {:?}", self.body))
    }
    pub fn reason(&self) -> &str {
        self.headers
            .get("x-weft-egress-reason")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

pub async fn send(sender: &mut SendRequest<Full<Bytes>>, req: Request<Full<Bytes>>) -> Answer {
    sender.ready().await.unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .expect("request timed out")
        .unwrap();
    let (parts, body) = resp.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

/// True when the gateway closes the connection without sending anything.
pub async fn closed_without_data<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> bool {
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) => false,
        Err(_) => panic!("connection neither closed nor answered"),
    }
}
