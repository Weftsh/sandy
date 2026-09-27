//! Command-line flags (with `WEFT_*` environment fallbacks) and their
//! validation into a [`Config`].
//!
//! Development seams (a static token, a static secrets file, routing
//! overrides, extra upstream roots) are refused unless `--dev` is given on
//! the command line. `--dev` deliberately has no environment fallback, so a
//! stray variable in a task definition cannot switch a production gateway
//! into development mode.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::Parser;
use weft_netpolicy::policy::normalize_hostname;

use crate::upstream::DevRouting;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "weft-egress-gateway",
    version,
    about = "Enforces Weft sandbox egress policy and injects credentials into allowlisted HTTPS APIs"
)]
pub struct Args {
    /// Address for PROXY-protocol connections from host agents.
    #[arg(long, env = "WEFT_EGRESS_LISTEN", default_value = "0.0.0.0:15000")]
    pub listen: SocketAddr,

    /// Address for the health endpoint (`GET /health`).
    #[arg(
        long,
        env = "WEFT_EGRESS_HEALTH_LISTEN",
        default_value = "0.0.0.0:15080"
    )]
    pub health_listen: SocketAddr,

    /// Control plane base URL, e.g. `https://control.internal.example`.
    #[arg(long, env = "WEFT_CONTROL_PLANE_URL")]
    pub control_plane_url: String,

    /// Server ID this gateway authenticates as (AWS IAM auth).
    #[arg(long, env = "WEFT_SERVER_ID")]
    pub server_id: Option<String>,

    /// AWS region for STS signing and AWS clients. Falls back to AWS_REGION.
    #[arg(long, env = "WEFT_AWS_REGION")]
    pub region: Option<String>,

    /// Authenticate to the control plane with a static token (requires --dev).
    #[arg(long, env = "WEFT_DEV_TOKEN", hide_env_values = true)]
    pub dev_token: Option<String>,

    /// Secrets Manager secret holding the interception CA as
    /// `{"certPem": "...", "keyPem": "..."}`.
    #[arg(long, env = "WEFT_CA_SECRET_ID")]
    pub ca_secret_id: Option<String>,

    /// Interception CA certificate (PEM file). Use with --ca-key-file.
    #[arg(long, env = "WEFT_CA_CERT_FILE")]
    pub ca_cert_file: Option<PathBuf>,

    /// Interception CA private key (PEM file). Use with --ca-cert-file.
    #[arg(long, env = "WEFT_CA_KEY_FILE")]
    pub ca_key_file: Option<PathBuf>,

    /// Most open connections across all sandboxes.
    #[arg(long, env = "WEFT_EGRESS_MAX_CONNECTIONS", default_value_t = 16384)]
    pub max_connections: usize,

    /// Most open connections per sandbox.
    #[arg(
        long,
        env = "WEFT_EGRESS_MAX_CONNECTIONS_PER_SANDBOX",
        default_value_t = 256
    )]
    pub max_connections_per_sandbox: usize,

    /// Upstream connect timeout, including DNS resolution.
    #[arg(long, env = "WEFT_EGRESS_CONNECT_TIMEOUT_SECS", default_value_t = 10)]
    pub connect_timeout_secs: u64,

    /// Close connections with no traffic in either direction for this long.
    #[arg(long, env = "WEFT_EGRESS_IDLE_TIMEOUT_SECS", default_value_t = 600)]
    pub idle_timeout_secs: u64,

    /// Development mode. Enables the --dev-* flags. Command line only.
    #[arg(long)]
    pub dev: bool,

    /// JSON object mapping secret IDs to secret strings, used instead of
    /// Secrets Manager (requires --dev).
    #[arg(long, env = "WEFT_DEV_SECRETS_FILE")]
    pub dev_secrets_file: Option<PathBuf>,

    /// After the policy allows HOST, connect to IP:PORT instead of resolving
    /// it (requires --dev; repeatable).
    #[arg(long = "dev-resolve", value_name = "HOST=IP:PORT")]
    pub dev_resolve: Vec<String>,

    /// After the policy allows original destination IP:PORT, connect to
    /// another address instead (requires --dev; repeatable).
    #[arg(long = "dev-redirect", value_name = "IP:PORT=IP:PORT")]
    pub dev_redirect: Vec<String>,

    /// Extra PEM roots trusted for upstream TLS (requires --dev).
    #[arg(long, env = "WEFT_DEV_UPSTREAM_CA_FILE")]
    pub dev_upstream_ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthConfig {
    AwsIam { region: String, server_id: String },
    DevToken(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaSource {
    SecretsManager(String),
    Files { cert: PathBuf, key: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretsConfig {
    SecretsManager,
    DevFile(PathBuf),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DevOptions {
    pub routing: DevRouting,
    pub upstream_ca_file: Option<PathBuf>,
}

/// Validated configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub health_listen: SocketAddr,
    pub control_plane_url: String,
    pub region: Option<String>,
    pub auth: AuthConfig,
    pub ca: CaSource,
    pub secrets: SecretsConfig,
    pub max_connections: usize,
    pub max_connections_per_sandbox: usize,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Present only with `--dev`.
    pub dev: Option<DevOptions>,
}

impl Config {
    pub fn from_args(args: Args) -> anyhow::Result<Self> {
        if !args.dev {
            let dev_only = [
                ("--dev-token", args.dev_token.is_some()),
                ("--dev-secrets-file", args.dev_secrets_file.is_some()),
                ("--dev-resolve", !args.dev_resolve.is_empty()),
                ("--dev-redirect", !args.dev_redirect.is_empty()),
                (
                    "--dev-upstream-ca-file",
                    args.dev_upstream_ca_file.is_some(),
                ),
            ];
            if let Some((flag, _)) = dev_only.iter().find(|(_, set)| *set) {
                bail!("{flag} is only allowed with --dev");
            }
        }

        let url = reqwest::Url::parse(&args.control_plane_url).context("--control-plane-url")?;
        if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
            bail!("--control-plane-url must be an http(s) URL");
        }

        let region = args
            .region
            .clone()
            .or_else(|| std::env::var("AWS_REGION").ok())
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .filter(|r| !r.is_empty());

        let auth = match (args.dev_token, args.server_id) {
            (Some(_), Some(_)) => bail!("use either --dev-token or --server-id, not both"),
            (Some(token), None) if token.is_empty() => bail!("--dev-token must not be empty"),
            (Some(token), None) => AuthConfig::DevToken(token),
            (None, Some(server_id)) => AuthConfig::AwsIam {
                region: region
                    .clone()
                    .context("--region (or AWS_REGION) is required for AWS IAM auth")?,
                server_id,
            },
            (None, None) => bail!("--server-id is required (or --dev-token with --dev)"),
        };

        let ca = match (args.ca_secret_id, args.ca_cert_file, args.ca_key_file) {
            (Some(id), None, None) => CaSource::SecretsManager(id),
            (None, Some(cert), Some(key)) => CaSource::Files { cert, key },
            (None, None, None) => {
                bail!("an interception CA is required: --ca-secret-id or --ca-cert-file with --ca-key-file")
            }
            _ => bail!("use either --ca-secret-id or --ca-cert-file with --ca-key-file"),
        };

        let secrets = match args.dev_secrets_file {
            Some(path) => SecretsConfig::DevFile(path),
            None => SecretsConfig::SecretsManager,
        };

        let dev = if args.dev {
            Some(DevOptions {
                routing: DevRouting {
                    resolve: args
                        .dev_resolve
                        .iter()
                        .map(|s| parse_resolve(s))
                        .collect::<anyhow::Result<_>>()?,
                    redirect: args
                        .dev_redirect
                        .iter()
                        .map(|s| parse_redirect(s))
                        .collect::<anyhow::Result<_>>()?,
                },
                upstream_ca_file: args.dev_upstream_ca_file,
            })
        } else {
            None
        };

        if args.max_connections == 0 || args.max_connections_per_sandbox == 0 {
            bail!("connection limits must be positive");
        }
        if args.connect_timeout_secs == 0 || args.idle_timeout_secs == 0 {
            bail!("timeouts must be positive");
        }

        Ok(Self {
            listen: args.listen,
            health_listen: args.health_listen,
            control_plane_url: args.control_plane_url,
            region,
            auth,
            ca,
            secrets,
            max_connections: args.max_connections,
            max_connections_per_sandbox: args.max_connections_per_sandbox,
            connect_timeout: Duration::from_secs(args.connect_timeout_secs),
            idle_timeout: Duration::from_secs(args.idle_timeout_secs),
            dev,
        })
    }
}

fn parse_resolve(s: &str) -> anyhow::Result<(String, SocketAddr)> {
    let (host, addr) = s
        .split_once('=')
        .with_context(|| format!("--dev-resolve {s:?}: expected HOST=IP:PORT"))?;
    let host = normalize_hostname(host)
        .with_context(|| format!("--dev-resolve: invalid host {host:?}"))?;
    let addr = addr
        .parse()
        .with_context(|| format!("--dev-resolve: invalid address {addr:?}"))?;
    Ok((host, addr))
}

fn parse_redirect(s: &str) -> anyhow::Result<(SocketAddr, SocketAddr)> {
    let (from, to) = s
        .split_once('=')
        .with_context(|| format!("--dev-redirect {s:?}: expected IP:PORT=IP:PORT"))?;
    Ok((
        from.parse()
            .with_context(|| format!("--dev-redirect: invalid address {from:?}"))?,
        to.parse()
            .with_context(|| format!("--dev-redirect: invalid address {to:?}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> anyhow::Result<Config> {
        let mut argv = vec![
            "weft-egress-gateway",
            "--control-plane-url",
            "http://127.0.0.1:9000",
            "--ca-cert-file",
            "/ca.pem",
            "--ca-key-file",
            "/ca.key",
        ];
        argv.extend_from_slice(extra);
        Config::from_args(Args::try_parse_from(argv)?)
    }

    #[test]
    fn dev_seams_require_dev() {
        for flags in [
            &["--dev-token", "t"][..],
            &[
                "--server-id",
                "gw",
                "--region",
                "us-east-1",
                "--dev-secrets-file",
                "/s.json",
            ],
            &[
                "--server-id",
                "gw",
                "--region",
                "us-east-1",
                "--dev-resolve",
                "a.example.com=127.0.0.1:1",
            ],
            &[
                "--server-id",
                "gw",
                "--region",
                "us-east-1",
                "--dev-redirect",
                "10.0.0.1:1=127.0.0.1:1",
            ],
            &[
                "--server-id",
                "gw",
                "--region",
                "us-east-1",
                "--dev-upstream-ca-file",
                "/r.pem",
            ],
        ] {
            let err = parse(flags).unwrap_err().to_string();
            assert!(err.contains("only allowed with --dev"), "{flags:?}: {err}");
        }
    }

    #[test]
    fn production_config_uses_aws_everything() {
        let c = parse(&["--server-id", "gw-1", "--region", "eu-west-1"]).unwrap();
        assert_eq!(
            c.auth,
            AuthConfig::AwsIam {
                region: "eu-west-1".into(),
                server_id: "gw-1".into()
            }
        );
        assert_eq!(c.secrets, SecretsConfig::SecretsManager);
        assert!(c.dev.is_none());
        assert_eq!(c.listen, "0.0.0.0:15000".parse().unwrap());
        assert_eq!(c.health_listen, "0.0.0.0:15080".parse().unwrap());
        assert_eq!(c.max_connections_per_sandbox, 256);
        assert_eq!(c.connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn dev_config_parses_routing() {
        let c = parse(&[
            "--dev",
            "--dev-token",
            "t",
            "--dev-resolve",
            "API.Example.com=127.0.0.1:8443",
            "--dev-redirect",
            "10.1.2.3:5432=127.0.0.1:15432",
        ])
        .unwrap();
        let dev = c.dev.unwrap();
        assert_eq!(
            dev.routing.resolve["api.example.com"],
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(
            dev.routing.redirect[&"10.1.2.3:5432".parse().unwrap()],
            "127.0.0.1:15432".parse().unwrap()
        );
        assert!(parse(&["--dev", "--dev-token", "t", "--dev-resolve", "nonsense"]).is_err());
    }

    #[test]
    fn requires_auth_and_exactly_one_ca_source() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["--dev", "--dev-token", "t", "--server-id", "gw"]).is_err());
        let no_ca = Args::try_parse_from([
            "weft-egress-gateway",
            "--control-plane-url",
            "http://cp",
            "--dev",
            "--dev-token",
            "t",
        ])
        .unwrap();
        assert!(Config::from_args(no_ca).is_err());
        assert!(parse(&["--dev", "--dev-token", "t", "--ca-secret-id", "x"]).is_err());
        let bad_url = Args::try_parse_from([
            "weft-egress-gateway",
            "--control-plane-url",
            "ftp://cp",
            "--dev",
            "--dev-token",
            "t",
            "--ca-secret-id",
            "x",
        ])
        .unwrap();
        assert!(Config::from_args(bad_url).is_err());
    }
}
