//! The host agent's control API, called only by the control plane.
//!
//! Served over TLS with the host's self-signed certificate and protected by
//! the host's bearer token. Security groups additionally restrict it to the
//! control plane. Sandboxes cannot reach it: all their TCP is redirected to
//! the egress forwarder.

use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::api_types::*;
use crate::manager::{Manager, ManagerError};
use crate::tls::tokens_equal;

#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<Manager>,
    pub token: Arc<String>,
    pub capacity: Capacity,
    pub version: &'static str,
}

impl IntoResponse for ManagerError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            Json(ErrorBody {
                code: status.as_u16(),
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/sandboxes", get(list))
        .route("/v1/sandboxes/{id}", put(start).delete(stop))
        .route("/v1/sandboxes/{id}/pause", post(pause))
        .route("/v1/sandboxes/{id}/egress", put(egress))
        .route("/v1/templates/{build_id}", post(build).get(build_status))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_token,
        ))
        .with_state(state)
}

async fn require_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !tokens_equal(presented.as_bytes(), state.token.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                code: 401,
                message: "invalid host token".into(),
            }),
        )
            .into_response();
    }
    next.run(req).await
}

async fn health(State(s): State<AppState>) -> Json<HostHealth> {
    Json(s.manager.health(s.capacity.clone(), s.version))
}

async fn list(State(s): State<AppState>) -> Json<Vec<SandboxInfo>> {
    Json(s.manager.list())
}

async fn start(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<StartSandboxRequest>,
) -> Result<Json<SandboxInfo>, ManagerError> {
    s.manager.start(&id, req).await.map(Json)
}

async fn stop(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ManagerError> {
    s.manager.stop(&id).await.map(|()| StatusCode::NO_CONTENT)
}

async fn pause(
    State(s): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<PauseRequest>>,
) -> Result<Json<PauseResult>, ManagerError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    s.manager.pause(&id, req).await.map(Json)
}

async fn egress(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(policy): Json<UpdateEgressRequest>,
) -> Result<StatusCode, ManagerError> {
    s.manager
        .update_egress(&id, &policy)
        .map(|()| StatusCode::NO_CONTENT)
}

async fn build(
    State(s): State<AppState>,
    Path(build_id): Path<String>,
    Json(req): Json<BuildTemplateRequest>,
) -> Result<StatusCode, ManagerError> {
    s.manager
        .start_build(&build_id, req)
        .map(|()| StatusCode::ACCEPTED)
}

async fn build_status(
    State(s): State<AppState>,
    Path(build_id): Path<String>,
) -> Result<Json<BuildStatus>, ManagerError> {
    s.manager.build_status(&build_id).map(Json)
}

/// Serves an axum router over TLS.
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(tcp),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    tracing::debug!(%peer, "TLS handshake failed");
                    return;
                }
            };
            let service = hyper_util::service::TowerToHyperService::new(app);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
    }
}
