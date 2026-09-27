//! `weft-egress-gateway`: see the library documentation for what it does.
//!
//! Logs, including the audit log, are JSON lines on stdout. `RUST_LOG`
//! adjusts verbosity; the default is `info`.

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use weft_egress_gateway::{health, Args, Config, Gateway};

/// ECS gives a task 30 seconds between SIGTERM and SIGKILL by default.
const DRAIN_GRACE: Duration = Duration::from_secs(25);

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stdout)
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "weft-egress-gateway failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let config = Config::from_args(args)?;
    if config.dev.is_some() {
        tracing::warn!("running in development mode; do not use in production");
    }
    if config.control_plane_url.starts_with("http://") && config.dev.is_none() {
        tracing::warn!(
            "the control plane URL is not HTTPS; internal credentials travel in clear text"
        );
    }
    let gateway = Gateway::from_config(&config).await?;
    let listener = TcpListener::bind(config.listen).await?;
    let health_listener = TcpListener::bind(config.health_listen).await?;
    tracing::info!(listen = %config.listen, health = %config.health_listen, "egress gateway started");

    tokio::spawn(health::serve(health_listener));
    gateway.clone().serve(listener, shutdown_signal()).await;

    tracing::info!(
        open = gateway.open_connections(),
        "shutting down; draining connections"
    );
    gateway.drain(DRAIN_GRACE).await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
