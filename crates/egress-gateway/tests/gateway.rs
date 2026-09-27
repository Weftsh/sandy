//! End-to-end tests of the gateway, in process, over loopback only.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Request, StatusCode};
use http_body_util::Full;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn deny_by_default_for_tls_http_and_opaque() {
    let env = Env::start().await;
    let sbx = env.id("empty");

    let tcp = env.connect("empty", &Env::named_dst(443)).await;
    let tls = tls_connect(
        tcp,
        "pass.example.com",
        &env.upstream_ca.cert_der,
        &[b"http/1.1"],
    )
    .await;
    assert!(
        tls.is_err(),
        "TLS to a name the policy does not allow must fail"
    );

    let tcp = env.connect("empty", &Env::named_dst(80)).await;
    let mut client = http_client(tcp).await;
    let answer = send(&mut client, get("plain.example.com", "/")).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.reason(), "not_allowed");

    let mut tcp = env.connect("empty", DB_DST).await;
    tcp.write_all(b"\x00\x01hello").await.unwrap();
    assert!(closed_without_data(&mut tcp).await);
    assert_eq!(env.banner_accepts.load(Ordering::SeqCst), 0);

    drop(client);
    let lines = wait_for_connections(&sbx, 3).await;
    let mut protocols: Vec<&str> = lines
        .iter()
        .map(|l| l["protocol"].as_str().unwrap())
        .collect();
    protocols.sort();
    assert_eq!(protocols, ["http", "opaque", "tls"]);
    assert!(
        lines
            .iter()
            .all(|l| l["decision"] == "deny" && l["reason"] == "not_allowed"),
        "{lines:?}"
    );
}

#[tokio::test]
async fn tls_passthrough_relays_bytes_to_the_resolved_name() {
    let env = Env::start().await;
    let sbx = env.id("web");

    // Only the upstream's own CA verifies: the gateway did not intercept.
    let tcp = env.connect("web", &Env::named_dst(443)).await;
    let tls = tls_connect(
        tcp,
        "pass.example.com",
        &env.upstream_ca.cert_der,
        &[b"http/1.1"],
    )
    .await
    .expect("passthrough handshake");
    let mut client = http_client(tls).await;
    let body = Bytes::from(vec![b'x'; 256 * 1024]);
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header(header::HOST, "pass.example.com")
        .body(Full::new(body))
        .unwrap();
    let answer = send(&mut client, req).await;
    assert_eq!(answer.status, StatusCode::OK);
    let doc = answer.json();
    assert_eq!(doc["bodyLen"], 256 * 1024);
    assert_eq!(doc["headers"]["host"][0], "pass.example.com");
    drop(client);

    let tcp = env.connect("web", &Env::named_dst(443)).await;
    let intercepted =
        tls_connect(tcp, "pass.example.com", &env.interception_ca.cert_der, &[]).await;
    assert!(
        intercepted.is_err(),
        "hosts without credentials are never intercepted"
    );

    let lines = wait_for_connections(&sbx, 2).await;
    let line = lines
        .iter()
        .find(|l| l["bytesUp"].as_u64().unwrap() > 256 * 1024)
        .expect("audit line of the upload connection");
    assert_eq!(line["decision"], "allow");
    assert_eq!(line["protocol"], "tls");
    assert_eq!(line["dstHost"], "pass.example.com");
    assert_eq!(line["intercepted"], false);
    assert!(line["bytesDown"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn http_keep_alive_checks_every_request() {
    let env = Env::start().await;
    let sbx = env.id("web");
    let tcp = env.connect("web", &Env::named_dst(80)).await;
    let mut client = http_client(tcp).await;

    let first = send(&mut client, get("plain.example.com", "/one?q=1")).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json()["path"], "/one?q=1");

    // Allowed by policy, but the connection is pinned to plain.example.com.
    let other = send(&mut client, get("other.example.com", "/")).await;
    assert_eq!(other.status, StatusCode::MISDIRECTED_REQUEST);

    let denied = send(&mut client, get("evil.example.net", "/")).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.reason(), "not_allowed");

    let port_change = send(&mut client, get("plain.example.com:8080", "/")).await;
    assert_eq!(port_change.status, StatusCode::MISDIRECTED_REQUEST);

    let again = send(&mut client, get("plain.example.com", "/two")).await;
    assert_eq!(again.status, StatusCode::OK);

    // A second Host header is a smuggling attempt.
    let smuggle = Request::builder()
        .uri("/")
        .header(header::HOST, "plain.example.com")
        .header(header::HOST, "other.example.com")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        send(&mut client, smuggle).await.status,
        StatusCode::BAD_REQUEST
    );
    drop(client);

    let requests = audit_lines(&sbx, "request");
    let statuses: Vec<u64> = requests
        .iter()
        .map(|r| r["status"].as_u64().unwrap())
        .collect();
    assert_eq!(statuses, [200, 421, 403, 421, 200, 400]);
    let conn = &wait_for_connections(&sbx, 1).await[0];
    assert_eq!(conn["decision"], "allow");
    assert_eq!(conn["requests"], 6);
    assert_eq!(conn["protocol"], "http");
}

#[tokio::test]
async fn http_upgrade_switches_to_raw_splice() {
    let env = Env::start().await;
    let tcp = env.connect("web", &Env::named_dst(80)).await;
    let mut client = http_client(tcp).await;
    let req = Request::builder()
        .uri("/ws")
        .header(header::HOST, "plain.example.com")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "echo")
        .body(Full::new(Bytes::new()))
        .unwrap();
    client.ready().await.unwrap();
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let upgraded = hyper::upgrade::on(resp).await.unwrap();
    let mut io = hyper_util::rt::TokioIo::new(upgraded);
    io.write_all(b"raw bytes after upgrade").await.unwrap();
    let mut buf = [0u8; 23];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"raw bytes after upgrade");

    // The upgrade target must still be checked like any request.
    let tcp = env.connect("web", &Env::named_dst(80)).await;
    let mut client = http_client(tcp).await;
    let req = Request::builder()
        .uri("/ws")
        .header(header::HOST, "evil.example.net")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "echo")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(send(&mut client, req).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn credential_proxy_injects_and_strips_and_pins_host() {
    let env = Env::start().await;
    let sbx = env.id("creds");
    let tcp = env.connect("creds", &Env::named_dst(443)).await;
    // The sandbox trusts the interception CA; the leaf must verify for the SNI.
    let tls = tls_connect(
        tcp,
        "creds.example.com",
        &env.interception_ca.cert_der,
        &[b"h2", b"http/1.1"],
    )
    .await
    .expect("interception handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let mut client = http_client(tls).await;

    let req = Request::builder()
        .uri("/v1/models")
        .header(header::HOST, "creds.example.com")
        .header(header::AUTHORIZATION, "Bearer sandbox-supplied-fake")
        .header("x-extra", "kept")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let answer = send(&mut client, req).await;
    assert_eq!(answer.status, StatusCode::OK);
    let doc = answer.json();
    let expected = format!("Bearer {}", env.secret_value);
    assert_eq!(
        doc["headers"]["authorization"],
        serde_json::json!([expected])
    );
    assert_eq!(doc["headers"]["x-extra"][0], "kept");
    assert_eq!(doc["path"], "/v1/models");

    // Lower-case duplicate headers are stripped too.
    let req = Request::builder()
        .uri("/")
        .header(header::HOST, "creds.example.com:443")
        .header("authorization", "one")
        .header("Authorization", "two")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let doc = send(&mut client, req).await.json();
    assert_eq!(
        doc["headers"]["authorization"],
        serde_json::json!([expected])
    );

    // Another host over the intercepted connection is refused, even one the
    // policy allows.
    let misdirected = send(&mut client, get("other.example.com", "/")).await;
    assert_eq!(misdirected.status, StatusCode::MISDIRECTED_REQUEST);
    assert!(!String::from_utf8_lossy(&misdirected.body).contains(&env.secret_value));

    let still_ok = send(&mut client, get("creds.example.com", "/after")).await;
    assert_eq!(still_ok.status, StatusCode::OK);

    // Request bodies stream through the credential proxy.
    let upload = Request::builder()
        .method("PUT")
        .uri("/upload")
        .header(header::HOST, "creds.example.com")
        .body(Full::new(Bytes::from(vec![7u8; 1024 * 1024])))
        .unwrap();
    let doc = send(&mut client, upload).await.json();
    assert_eq!(doc["bodyLen"], 1024 * 1024);
    assert_eq!(
        doc["headers"]["authorization"],
        serde_json::json!([expected])
    );
    drop(client);

    let requests = audit_lines(&sbx, "request");
    let injected: Vec<bool> = requests
        .iter()
        .map(|r| r["credentialInjected"].as_bool().unwrap())
        .collect();
    assert_eq!(injected, [true, true, false, true, true]);
    let conn = &wait_for_connections(&sbx, 1).await[0];
    assert_eq!(conn["intercepted"], true);
    assert_eq!(conn["credentialInjected"], true);
    assert_eq!(conn["decision"], "allow");
}

#[tokio::test]
async fn credential_proxy_fails_closed_without_the_secret() {
    let env = Env::start().await;
    let tcp = env.connect("nosecret", &Env::named_dst(443)).await;
    let tls = tls_connect(
        tcp,
        "pass.example.com",
        &env.interception_ca.cert_der,
        &[b"http/1.1"],
    )
    .await
    .expect("interception handshake");
    let mut client = http_client(tls).await;
    let req = Request::builder()
        .uri("/")
        .header(header::HOST, "pass.example.com")
        .header("x-api-key", "sandbox-supplied")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let answer = send(&mut client, req).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(answer.reason(), "credential_unavailable");
    drop(client);
    let conn = &wait_for_connections(&env.id("nosecret"), 1).await[0];
    assert_eq!(conn["decision"], "deny");
    assert_eq!(conn["upstream"], "", "nothing was forwarded");
}

#[tokio::test]
async fn credential_proxy_client_must_trust_the_interception_ca() {
    let env = Env::start().await;
    let tcp = env.connect("creds", &Env::named_dst(443)).await;
    let result = tls_connect(
        tcp,
        "creds.example.com",
        &env.upstream_ca.cert_der,
        &[b"http/1.1"],
    )
    .await;
    assert!(
        result.is_err(),
        "the leaf is signed by the interception CA, not the upstream's"
    );
}

#[tokio::test]
async fn secret_values_never_reach_the_logs() {
    let env = Env::start().await;
    let sbx = env.id("creds");
    for _ in 0..2 {
        let tcp = env.connect("creds", &Env::named_dst(443)).await;
        let tls = tls_connect(
            tcp,
            "creds.example.com",
            &env.interception_ca.cert_der,
            &[b"http/1.1"],
        )
        .await
        .unwrap();
        let mut client = http_client(tls).await;
        assert_eq!(
            send(&mut client, get("creds.example.com", "/"))
                .await
                .status,
            StatusCode::OK
        );
    }
    let lines = wait_for_connections(&sbx, 2).await;
    assert!(lines.iter().all(|l| l["credentialInjected"] == true));
    let logs = logs();
    assert!(logs.contains(&sbx), "log capture is working");
    assert!(
        !logs.contains(&env.secret_value),
        "a secret value was logged"
    );
}

#[tokio::test]
async fn forbidden_addresses_are_denied_even_with_a_wildcard_policy() {
    let env = Env::start().await;
    let sbx = env.id("star");

    let mut imds = env.connect("star", "169.254.169.254:80").await;
    imds.write_all(b"\x00ping").await.unwrap();
    assert!(closed_without_data(&mut imds).await);

    // A real, listening loopback service.
    let mut lo = env.connect("star", &env.banner_addr.to_string()).await;
    lo.write_all(b"\x00ping").await.unwrap();
    assert!(closed_without_data(&mut lo).await);
    assert_eq!(env.banner_accepts.load(Ordering::SeqCst), 0);

    // Names that resolve to loopback are denied after resolution.
    let tcp = env.connect("star", &Env::named_dst(80)).await;
    let mut client = http_client(tcp).await;
    let answer = send(&mut client, get("localhost", "/")).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.reason(), "forbidden_address");
    drop(client);

    let tcp = env.connect("star", &Env::named_dst(443)).await;
    assert!(
        tls_connect(tcp, "localhost", &env.upstream_ca.cert_der, &[])
            .await
            .is_err()
    );

    let lines = wait_for_connections(&sbx, 4).await;
    assert!(
        lines
            .iter()
            .all(|l| l["decision"] == "deny" && l["reason"] == "forbidden_address"),
        "{lines:#?}"
    );
}

#[tokio::test]
async fn opaque_server_speaks_first_traffic_uses_the_ip_rule() {
    let env = Env::start().await;
    let mut tcp = env.connect("db", DB_DST).await;
    let mut banner = vec![0u8; BANNER.len()];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut banner))
        .await
        .expect("banner after the first-byte timeout")
        .unwrap();
    assert_eq!(banner, BANNER);
    tcp.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    tcp.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    drop(tcp);

    let conn = &wait_for_connections(&env.id("db"), 1).await[0];
    assert_eq!(conn["protocol"], "opaque");
    assert_eq!(conn["decision"], "allow");
    assert_eq!(conn["dst"], DB_DST);
    assert_eq!(conn["bytesUp"], 4);
    assert_eq!(conn["bytesDown"], (BANNER.len() + 4) as u64);

    // The same destination on a port the rule does not list.
    let mut other_port = env.connect("db", "10.99.0.7:2223").await;
    other_port.write_all(b"\x00").await.unwrap();
    assert!(closed_without_data(&mut other_port).await);
}

#[tokio::test]
async fn connections_from_the_wrong_host_are_denied() {
    let env = Env::start().await;
    let mut tcp = env.connect("elsewhere", &Env::named_dst(80)).await;
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(closed_without_data(&mut tcp).await);
    let line = &wait_for_connections(&env.id("elsewhere"), 1).await[0];
    assert_eq!(line["reason"], "host_mismatch");
    assert_eq!(line["peer"], "127.0.0.1");
}

#[tokio::test]
async fn unknown_sandboxes_and_bad_policies_are_denied() {
    let env = Env::start().await;
    for (name, reason) in [
        ("nope", "unknown_sandbox"),
        ("invalid", "invalid_policy"),
        ("confused", "control_plane_error"),
    ] {
        let mut tcp = env.connect(name, &Env::named_dst(80)).await;
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(closed_without_data(&mut tcp).await, "{name}");
        let line = &wait_for_connections(&env.id(name), 1).await[0];
        assert_eq!(line["reason"], reason, "{name}");
    }
}

#[tokio::test]
async fn malformed_proxy_headers_are_rejected() {
    let env = Env::start().await;
    let before = env.control_plane_hits.load(Ordering::SeqCst);

    let mut tcp = tokio::net::TcpStream::connect(env.gateway).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(closed_without_data(&mut tcp).await);

    // Valid signature, LOCAL command.
    let mut header = weft_netpolicy::ProxyHeader {
        source: "10.200.0.2:1".parse().unwrap(),
        destination: "10.99.0.1:80".parse().unwrap(),
        sandbox_id: env.id("web"),
    }
    .encode()
    .unwrap();
    header[12] = 0x20;
    let mut tcp = tokio::net::TcpStream::connect(env.gateway).await.unwrap();
    tcp.write_all(&header).await.unwrap();
    assert!(closed_without_data(&mut tcp).await);

    // Truncated header, then nothing.
    let mut tcp = tokio::net::TcpStream::connect(env.gateway).await.unwrap();
    tcp.write_all(&weft_netpolicy::proxy_protocol::SIGNATURE)
        .await
        .unwrap();
    tcp.shutdown().await.unwrap();
    assert!(closed_without_data(&mut tcp).await);

    assert_eq!(env.control_plane_hits.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn policy_lookups_are_cached() {
    let env = Env::start().await;
    for _ in 0..3 {
        let tcp = env.connect("web", &Env::named_dst(80)).await;
        let mut client = http_client(tcp).await;
        assert_eq!(
            send(&mut client, get("plain.example.com", "/"))
                .await
                .status,
            StatusCode::OK
        );
    }
    assert_eq!(env.control_plane_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn per_sandbox_connection_limit() {
    let env = Env::start_with(&["--max-connections-per-sandbox", "1"]).await;
    let tcp = env.connect("web", &Env::named_dst(80)).await;
    let mut held = http_client(tcp).await;
    assert_eq!(
        send(&mut held, get("plain.example.com", "/")).await.status,
        StatusCode::OK
    );

    let mut second = env.connect("web", &Env::named_dst(80)).await;
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(closed_without_data(&mut second).await);
    let lines = wait_for_connections(&env.id("web"), 1).await;
    assert_eq!(lines[0]["reason"], "too_many_connections");

    // Other sandboxes are unaffected.
    let tcp = env.connect("star", &Env::named_dst(80)).await;
    let mut client = http_client(tcp).await;
    assert_eq!(
        send(&mut client, get("localhost", "/")).await.reason(),
        "forbidden_address"
    );
    drop(held);
}

#[tokio::test]
async fn health_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(weft_egress_gateway::health::serve(listener));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut client = http_client(tcp).await;
    assert_eq!(
        send(&mut client, get("gw", "/health")).await.status,
        StatusCode::OK
    );
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut client = http_client(tcp).await;
    assert_eq!(
        send(&mut client, get("gw", "/other")).await.status,
        StatusCode::NOT_FOUND
    );
}
