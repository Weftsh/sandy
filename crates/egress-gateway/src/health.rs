//! The health endpoint for the load balancer: `GET /health` answers 200.
//! It listens on its own port so health checks never touch the sandbox
//! listener, which only speaks PROXY protocol.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

pub async fn serve(listener: TcpListener) {
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(e) => {
                tracing::warn!(error = %e, "health accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        tokio::spawn(async move {
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .keep_alive(false)
                .serve_connection(TokioIo::new(tcp), service_fn(respond));
            let _ = tokio::time::timeout(Duration::from_secs(10), conn).await;
        });
    }
}

async fn respond<B>(req: Request<B>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, body) = match (req.method(), req.uri().path()) {
        (&Method::GET | &Method::HEAD, "/health") => (StatusCode::OK, "ok\n"),
        _ => (StatusCode::NOT_FOUND, "not found\n"),
    };
    let mut resp = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    Ok(resp)
}
