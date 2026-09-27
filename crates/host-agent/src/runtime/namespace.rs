//! Development runtime: envd in Linux namespaces on the host kernel.
//!
//! **This is not a security boundary.** Guests share the host kernel and run
//! as root. It exists so the full stack, including the unmodified E2B SDKs,
//! the network rules, the guest resolver, the egress gateway and the
//! credential proxy, can be exercised on machines without KVM (laptops, CI).
//! The agent refuses to use it unless `--insecure-namespace-runtime` is set.
//!
//! Each guest gets an overlay of the template's root filesystem, its own
//! network namespace (with the same addresses as a microVM), and new mount,
//! PID, UTS and IPC namespaces. Pause freezes the guest's cgroup in place.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use super::{Result, RuntimeError, StartSpec};
use crate::envd::ENVD_PORT;
use crate::net::{GuestLink, Slot, GUEST_GATEWAY};
use crate::rootfs::{GUEST_ENVD_PATH, GUEST_INIT_PATH};

pub struct NamespaceRuntime {
    data_dir: PathBuf,
    freezer: Freezer,
}

pub struct NsHandle {
    child: Child,
    dir: PathBuf,
    cgroup: Option<PathBuf>,
}

/// Which cgroup freezer the host offers.
#[derive(Clone, Debug)]
enum Freezer {
    V2 { root: PathBuf },
    V1 { root: PathBuf },
    None,
}

impl Freezer {
    fn detect() -> Self {
        let v2 = Path::new("/sys/fs/cgroup/cgroup.controllers");
        if v2.exists() {
            return Freezer::V2 {
                root: PathBuf::from("/sys/fs/cgroup/weft"),
            };
        }
        let v1 = Path::new("/sys/fs/cgroup/freezer");
        if v1.join("cgroup.procs").exists() {
            return Freezer::V1 {
                root: v1.join("weft"),
            };
        }
        Freezer::None
    }
}

impl NamespaceRuntime {
    pub fn new(data_dir: PathBuf) -> Self {
        let freezer = Freezer::detect();
        tracing::warn!(
            ?freezer,
            "namespace runtime enabled: sandboxes share the host kernel and are NOT isolated; use only for development and CI"
        );
        Self { data_dir, freezer }
    }

    /// Kills guests left behind by a previous agent process (crash, restart)
    /// and removes their cgroups.
    pub async fn cleanup_leftovers(&self) {
        let root = match &self.freezer {
            Freezer::V2 { root } | Freezer::V1 { root } => root.clone(),
            Freezer::None => return,
        };
        let Ok(mut entries) = tokio::fs::read_dir(&root).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let cg = entry.path();
            if !cg.is_dir() {
                continue;
            }
            let _ = self.set_frozen(&cg, false).await;
            kill_cgroup(&cg).await;
            let _ = tokio::fs::remove_dir(&cg).await;
            tracing::info!(cgroup = %cg.display(), "removed leftover sandbox");
        }
    }

    pub fn guest_link(&self, slot: &Slot) -> GuestLink {
        GuestLink::Veth {
            guest_netns: format!("weft-g{}", slot.index),
        }
    }

    pub async fn finish_template(&self, rootfs_dir: &Path, out_dir: &Path) -> Result<()> {
        tokio::fs::create_dir_all(out_dir).await?;
        tokio::fs::rename(rootfs_dir, out_dir.join("rootfs")).await?;
        Ok(())
    }

    pub async fn start(&self, spec: StartSpec<'_>) -> Result<NsHandle> {
        if spec.snapshot.is_some() {
            return Err(RuntimeError::Unsupported {
                runtime: "namespace",
                what: "resuming from snapshot files",
            });
        }
        let dir = self.data_dir.join("sandboxes").join(spec.sandbox_id);
        let (upper, work, merged) = (dir.join("upper"), dir.join("work"), dir.join("rootfs"));
        for d in [&upper, &work, &merged] {
            tokio::fs::create_dir_all(d).await?;
        }
        let lower = spec.template.dir.join("rootfs");
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );
        nix::mount::mount(
            Some("overlay"),
            &merged,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(opts.as_str()),
        )
        .map_err(|e| RuntimeError::Failed(format!("mounting overlay: {e}")))?;

        let cgroup = self.create_cgroup(spec.sandbox_id).await?;
        let GuestLink::Veth { guest_netns } = self.guest_link(spec.slot) else {
            unreachable!()
        };
        let agent = std::env::current_exe()?;
        let mut cmd = Command::new(agent);
        cmd.arg("enter-cgroup")
            .arg(
                cgroup
                    .as_ref()
                    .map(|c| c.join("cgroup.procs"))
                    .unwrap_or_default(),
            )
            .arg("--")
            .args(["ip", "netns", "exec", &guest_netns])
            .args([
                "unshare",
                "--mount",
                "--pid",
                "--uts",
                "--ipc",
                "--fork",
                "--kill-child",
            ])
            .arg(format!("--root={}", merged.display()))
            .arg("--wd=/")
            .arg(format!("/{GUEST_INIT_PATH}"))
            .args([
                "--mode",
                "namespace",
                "--hostname",
                &hostname(spec.sandbox_id),
            ])
            .args(["--dns", &GUEST_GATEWAY.to_string()])
            .args(["--envd", &format!("/{GUEST_ENVD_PATH}")])
            // -isnotfc: no Firecracker metadata service. -no-cgroups: envd
            // must not reconfigure the host's cgroups.
            .args(["--envd-arg", "-isnotfc", "--envd-arg", "-no-cgroups"])
            .args(["--envd-arg", "-port", "--envd-arg", &ENVD_PORT.to_string()])
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn()?;
        forward_output(spec.sandbox_id, &mut child);
        Ok(NsHandle { child, dir, cgroup })
    }

    pub async fn stop(&self, mut h: NsHandle) -> Result<()> {
        if let Some(cg) = &h.cgroup {
            let _ = self.set_frozen(cg, false).await;
        }
        let _ = h.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), h.child.wait()).await;
        if let Some(cg) = &h.cgroup {
            kill_cgroup(cg).await;
            for _ in 0..50 {
                if tokio::fs::remove_dir(cg).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let merged = h.dir.join("rootfs");
        let _ = nix::mount::umount2(&merged, nix::mount::MntFlags::MNT_DETACH);
        tokio::fs::remove_dir_all(&h.dir)
            .await
            .or_else(ignore_missing)?;
        Ok(())
    }

    pub async fn freeze(&self, h: &NsHandle) -> Result<()> {
        let cg = h.cgroup.as_ref().ok_or(RuntimeError::Unsupported {
            runtime: "namespace",
            what: "pause without a cgroup freezer on this host",
        })?;
        self.set_frozen(cg, true).await
    }

    pub async fn thaw(&self, h: &NsHandle) -> Result<()> {
        let cg = h.cgroup.as_ref().ok_or(RuntimeError::Unsupported {
            runtime: "namespace",
            what: "resume",
        })?;
        self.set_frozen(cg, false).await
    }

    async fn create_cgroup(&self, id: &str) -> Result<Option<PathBuf>> {
        let root = match &self.freezer {
            Freezer::V2 { root } | Freezer::V1 { root } => root,
            Freezer::None => return Ok(None),
        };
        let cg = root.join(id);
        tokio::fs::create_dir_all(&cg).await?;
        Ok(Some(cg))
    }

    async fn set_frozen(&self, cg: &Path, frozen: bool) -> Result<()> {
        match &self.freezer {
            Freezer::V2 { .. } => {
                tokio::fs::write(cg.join("cgroup.freeze"), if frozen { "1" } else { "0" }).await?;
                wait_for(
                    cg.join("cgroup.events"),
                    if frozen { "frozen 1" } else { "frozen 0" },
                )
                .await
            }
            Freezer::V1 { .. } => {
                let want = if frozen { "FROZEN" } else { "THAWED" };
                tokio::fs::write(cg.join("freezer.state"), want).await?;
                wait_for(cg.join("freezer.state"), want).await
            }
            Freezer::None => Err(RuntimeError::Unsupported {
                runtime: "namespace",
                what: "freezing",
            }),
        }
    }
}

async fn wait_for(file: PathBuf, needle: &str) -> Result<()> {
    for _ in 0..200 {
        if tokio::fs::read_to_string(&file)
            .await
            .unwrap_or_default()
            .contains(needle)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(RuntimeError::Failed(format!(
        "{} never reported {needle}",
        file.display()
    )))
}

async fn kill_cgroup(cg: &Path) {
    // cgroup v2 has a one-shot kill; v1 needs every pid signalled.
    if tokio::fs::write(cg.join("cgroup.kill"), "1").await.is_ok() {
        return;
    }
    for _ in 0..20 {
        let procs = tokio::fs::read_to_string(cg.join("cgroup.procs"))
            .await
            .unwrap_or_default();
        if procs.trim().is_empty() {
            return;
        }
        for pid in procs.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn ignore_missing(e: std::io::Error) -> std::io::Result<()> {
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(e)
    }
}

/// Short hostname for the guest: `sandbox` plus the first ID characters.
fn hostname(id: &str) -> String {
    let short: String = id.chars().take(12).collect();
    format!("sb-{short}")
}

/// Logs guest output at debug level, one line at a time, bounded per line.
fn forward_output(sandbox_id: &str, child: &mut Child) {
    let id = sandbox_id.to_owned();
    if let Some(out) = child.stdout.take() {
        let id = id.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(sandbox = %id, stream = "stdout", line = %truncate(&line));
            }
        });
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(sandbox = %id, stream = "stderr", line = %truncate(&line));
            }
        });
    }
}

fn truncate(s: &str) -> &str {
    let mut end = s.len().min(1024);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// `weft-host-agent enter-cgroup <procs-file> -- <command...>`: joins the
/// cgroup (when a path is given), then replaces itself with the command, so
/// every process the guest creates is in the cgroup from the start.
pub fn enter_cgroup_and_exec(procs_file: &str, argv: &[String]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    if !procs_file.is_empty() {
        if let Err(e) = std::fs::write(procs_file, std::process::id().to_string()) {
            return e;
        }
    }
    let Some((program, args)) = argv.split_first() else {
        return std::io::Error::new(std::io::ErrorKind::InvalidInput, "no command given");
    };
    std::process::Command::new(program).args(args).exec()
}
