//! Weft host agent: runs sandboxes on one EC2 host.
//!
//! ```text
//! weft-host-agent run [flags]                              the agent
//! weft-host-agent unpack-layer <root> <layer> <media-type>  internal: chrooted layer extraction
//! weft-host-agent prepare-rootfs <root> <guest-dir>        internal: chrooted guest setup
//! weft-host-agent enter-cgroup <procs-file> -- <cmd...>     internal: join a cgroup, then exec
//! ```

mod api;
mod api_types;
mod artifacts;
mod cmd;
mod dns;
mod egress;
mod envd;
mod manager;
mod net;
mod oci;
mod register;
mod rootfs;
mod runtime;
mod slots;
mod tls;
mod tunnel;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use crate::api_types::Capacity;
use crate::manager::{Manager, ManagerConfig};
use crate::net::NetConfig;
use crate::runtime::firecracker::{FirecrackerConfig, FirecrackerRuntime};
use crate::runtime::namespace::NamespaceRuntime;
use crate::runtime::Runtime;
use crate::slots::SlotTable;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Version of the envd binary shipped in `guest/envd/VERSION`.
pub const ENVD_VERSION: &str = "0.9.0";

#[derive(Parser)]
#[command(
    name = "weft-host-agent",
    version,
    about = "Runs Weft sandboxes on one host"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent.
    Run(Box<RunArgs>),
    #[command(hide = true)]
    UnpackLayer {
        root: PathBuf,
        layer: PathBuf,
        media_type: String,
    },
    #[command(hide = true)]
    PrepareRootfs { root: PathBuf, guest_dir: PathBuf },
    #[command(hide = true)]
    EnterCgroup {
        procs_file: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum RuntimeKind {
    Firecracker,
    Namespace,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum AuthKind {
    AwsIam,
    DevToken,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Unique host ID; on EC2, the instance ID.
    #[arg(long, env = "WEFT_HOST_ID")]
    host_id: String,
    /// Address the control plane and edge proxy use to reach this host.
    #[arg(long, env = "WEFT_PRIVATE_IP")]
    private_ip: String,
    #[arg(long, env = "WEFT_CONTROL_PLANE_URL")]
    control_plane_url: String,
    #[arg(long, env = "WEFT_AUTH", value_enum, default_value = "aws-iam")]
    auth: AuthKind,
    /// Server ID the control plane expects in signed IAM requests.
    #[arg(long, env = "WEFT_SERVER_ID", default_value = "weft-control-plane")]
    server_id: String,
    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    region: String,
    /// Shared token for `--auth dev-token` (development only).
    #[arg(long, env = "WEFT_DEV_TOKEN")]
    dev_token: Option<String>,

    #[arg(long, env = "WEFT_RUNTIME", value_enum, default_value = "firecracker")]
    runtime: RuntimeKind,
    /// Required to use the namespace runtime, which does not isolate sandboxes.
    #[arg(long, env = "WEFT_INSECURE_NAMESPACE_RUNTIME")]
    insecure_namespace_runtime: bool,

    #[arg(long, env = "WEFT_DATA_DIR", default_value = "/var/lib/weft")]
    data_dir: PathBuf,
    /// Directory with `envd` and `weft-guest-init` for new templates.
    #[arg(long, env = "WEFT_GUEST_DIR", default_value = "/opt/weft/guest")]
    guest_dir: PathBuf,

    #[arg(long, env = "WEFT_API_LISTEN", default_value = "0.0.0.0:5007")]
    api_listen: SocketAddr,
    #[arg(long, env = "WEFT_TUNNEL_LISTEN", default_value = "0.0.0.0:5008")]
    tunnel_listen: SocketAddr,
    /// `host:port` of the egress gateway.
    #[arg(long, env = "WEFT_EGRESS_GATEWAY")]
    egress_gateway: String,
    #[arg(long, env = "WEFT_EGRESS_PORT", default_value_t = 15001)]
    egress_port: u16,
    #[arg(long, env = "WEFT_DNS_PORT", default_value_t = 15053)]
    dns_port: u16,
    /// Upstream resolver; defaults to the first nameserver in /etc/resolv.conf.
    #[arg(long, env = "WEFT_DNS_UPSTREAM")]
    dns_upstream: Option<SocketAddr>,
    /// Pool for per-sandbox links. Must not overlap the VPC.
    #[arg(long, env = "WEFT_SLOT_POOL", default_value = "10.200.0.0/16")]
    slot_pool: String,
    #[arg(long, env = "WEFT_MAX_SANDBOXES", default_value_t = 64)]
    max_sandboxes: u32,
    /// Host memory kept back from sandboxes for the OS, the agent and page
    /// cache (Firecracker runtime).
    #[arg(long, env = "WEFT_MEMORY_RESERVE_MIB", default_value_t = 2048)]
    memory_reserve_mib: u64,
    /// Ratio of guest memory to commit against the rest of host memory.
    /// Above 1.0 overcommits, which relies on guests not touching all of
    /// their memory.
    #[arg(long, env = "WEFT_MEMORY_OVERCOMMIT", default_value_t = 1.0)]
    memory_overcommit: f64,

    #[arg(
        long,
        env = "WEFT_FIRECRACKER_BIN",
        default_value = "/usr/local/bin/firecracker"
    )]
    firecracker_bin: PathBuf,
    #[arg(long, env = "WEFT_JAILER_BIN", default_value = "/usr/local/bin/jailer")]
    jailer_bin: PathBuf,
    #[arg(long, env = "WEFT_KERNEL", default_value = "/opt/weft/guest/vmlinux")]
    kernel: PathBuf,
    #[arg(long, env = "WEFT_CHROOT_BASE", default_value = "/var/lib/weft/jail")]
    chroot_base: PathBuf,
    #[arg(long, env = "WEFT_UID_BASE", default_value_t = 200_000)]
    uid_base: u32,
    /// Firecracker CPU template (JSON) applied to template builds, so every
    /// host that restores a snapshot presents the same CPU features.
    #[arg(long, env = "WEFT_CPU_TEMPLATE")]
    cpu_template: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::UnpackLayer {
            root,
            layer,
            media_type,
        } => match rootfs::unpack_layer_in_chroot(&root, &layer, &media_type) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        Command::PrepareRootfs { root, guest_dir } => {
            match rootfs::prepare_in_chroot(&root, &guest_dir) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::EnterCgroup {
            procs_file,
            command,
        } => {
            let err = runtime::namespace::enter_cgroup_and_exec(&procs_file, &command);
            eprintln!("enter-cgroup: {err}");
            ExitCode::FAILURE
        }
        Command::Run(args) => {
            tracing_subscriber::fmt()
                .json()
                .flatten_event(true)
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            match rt.block_on(run(*args)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "host agent failed");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    // One agent per host: a second one would tear down the first one's
    // namespaces and iptables rules.
    std::fs::create_dir_all(&args.data_dir)?;
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(args.data_dir.join(".agent.lock"))?;
    let _lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| {
            anyhow::anyhow!(
                "another host agent is running with data dir {} ({e})",
                args.data_dir.display()
            )
        })?;
    let net = NetConfig {
        pool: args
            .slot_pool
            .parse()
            .map_err(|e: String| anyhow::anyhow!("--slot-pool: {e}"))?,
        dns_port: args.dns_port,
        egress_port: args.egress_port,
    };
    let runtime = match args.runtime {
        RuntimeKind::Namespace => {
            anyhow::ensure!(
                args.insecure_namespace_runtime,
                "the namespace runtime does not isolate sandboxes; pass --insecure-namespace-runtime to use it for development"
            );
            Runtime::Namespace(NamespaceRuntime::new(args.data_dir.clone()))
        }
        RuntimeKind::Firecracker => {
            Runtime::Firecracker(FirecrackerRuntime::new(FirecrackerConfig {
                firecracker_bin: args.firecracker_bin.clone(),
                jailer_bin: args.jailer_bin.clone(),
                kernel: args.kernel.clone(),
                chroot_base: args.chroot_base.clone(),
                data_dir: args.data_dir.clone(),
                uid_base: args.uid_base,
                cpu_template: args.cpu_template.clone(),
                ..Default::default()
            })?)
        }
    };
    let auth = match args.auth {
        AuthKind::AwsIam => weft_awsauth::InternalAuth::AwsIam(
            weft_awsauth::AwsIamSigner::from_default_chain(&args.region, &args.server_id).await?,
        ),
        AuthKind::DevToken => weft_awsauth::InternalAuth::DevToken(
            args.dev_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--dev-token is required with --auth dev-token"))?,
        ),
    };

    let memory_total = memory_mib().unwrap_or(0);
    let memory_budget_mib = match args.runtime {
        // The namespace runtime does not reserve guest memory.
        RuntimeKind::Namespace => None,
        RuntimeKind::Firecracker => {
            anyhow::ensure!(
                args.memory_overcommit > 0.0 && args.memory_overcommit <= 4.0,
                "--memory-overcommit must be above 0 and at most 4"
            );
            let usable = memory_total.saturating_sub(args.memory_reserve_mib);
            Some((usable as f64 * args.memory_overcommit) as u64)
        }
    };
    let capacity = Capacity {
        max_sandboxes: args.max_sandboxes,
        vcpus: std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1),
        memory_mib: memory_total,
        memory_budget_mib,
    };
    let slots = Arc::new(SlotTable::new(net.clone(), args.max_sandboxes));
    let manager = Arc::new(Manager::new(
        ManagerConfig {
            host_id: args.host_id.clone(),
            data_dir: args.data_dir.clone(),
            guest_dir: args.guest_dir.clone(),
            max_vcpus: capacity.vcpus,
            max_memory_mib: (capacity.memory_mib as u32).max(1024),
            memory_budget_mib,
        },
        runtime,
        slots.clone(),
    ));
    manager.recover().await?;

    let identity = tls::generate(&args.private_ip)?;
    let token = Arc::new(tls::random_token());

    let upstream = match args.dns_upstream {
        Some(a) => a,
        None => dns::upstream_from_resolv_conf(
            &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
        )
        .ok_or_else(|| anyhow::anyhow!("no nameserver in /etc/resolv.conf; set --dns-upstream"))?,
    };
    let resolver = Arc::new(dns::Resolver::new(slots.clone(), upstream));
    let dns_addr = SocketAddr::from(([0, 0, 0, 0], args.dns_port));
    tokio::spawn(
        resolver
            .clone()
            .serve_udp(tokio::net::UdpSocket::bind(dns_addr).await?),
    );
    tokio::spawn(resolver.serve_tcp(tokio::net::TcpListener::bind(dns_addr).await?));

    let forwarder = Arc::new(egress::Forwarder::new(
        slots.clone(),
        args.egress_gateway.clone(),
    ));
    tokio::spawn(forwarder.serve(
        tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], args.egress_port))).await?,
    ));

    let tunnel = Arc::new(tunnel::Tunnel {
        manager: manager.clone(),
        token: token.clone(),
        tls: identity.server_config.clone(),
    });
    tokio::spawn(tunnel.serve(tokio::net::TcpListener::bind(args.tunnel_listen).await?));

    let app = api::router(api::AppState {
        manager: manager.clone(),
        token: token.clone(),
        capacity: capacity.clone(),
        version: VERSION,
    });
    tokio::spawn(api::serve_tls(
        tokio::net::TcpListener::bind(args.api_listen).await?,
        identity.server_config.clone(),
        app,
    ));

    let registration = register::Registration {
        control_plane_url: args.control_plane_url.clone(),
        auth: Arc::new(weft_awsauth::HeaderCache::new(auth)),
        host_id: args.host_id.clone(),
        private_ip: args.private_ip.clone(),
        api_port: args.api_listen.port(),
        tunnel_port: args.tunnel_listen.port(),
        cert_pem: identity.cert_pem.clone(),
        token,
        capacity,
        version: VERSION,
    };
    tracing::info!(host = %args.host_id, runtime = manager.runtime_name(), "host agent started");
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        () = registration.run(manager.clone()) => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down; stopping sandboxes");
    manager.shutdown().await;
    Ok(())
}

fn memory_mib() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb / 1024)
}

#[cfg(test)]
mod tests {
    #[test]
    fn envd_version_matches_the_pinned_build() {
        let pinned = include_str!("../../../guest/envd/VERSION");
        assert!(pinned
            .lines()
            .any(|l| l == format!("ENVD_VERSION={}", super::ENVD_VERSION)));
    }
}
