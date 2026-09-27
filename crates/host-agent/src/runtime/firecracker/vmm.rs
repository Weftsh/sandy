//! One jail and the Firecracker process in it, from an empty chroot to
//! teardown.
//!
//! [`Jail::create`] clears anything left under the same ID (a crashed agent,
//! a failed earlier attempt) and creates an empty chroot for the caller to
//! fill. [`Jail::launch`] runs the jailer, whose stdout and stderr, inherited
//! by Firecracker, feed the console ring buffer. [`Jail::destroy`] kills the
//! VMM and removes the chroot and the cgroup. A jail dropped without
//! `destroy` kills its VMM and cleans up in the background.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::task::JoinHandle;

use super::api::ApiClient;
use super::console::{ConsoleLog, CONSOLE_CAPACITY, ERROR_TAIL};
use super::jail::{cgroup_populated, cleanup_plan, kill_plan, run_cleanup, vmm_alive, JailPaths};
use crate::runtime::RuntimeError;

pub struct Jail {
    paths: JailPaths,
    /// Firecracker's host PID, once the jailer has reported it.
    pid: Option<i32>,
    console: Arc<ConsoleLog>,
    readers: Vec<JoinHandle<()>>,
    api: ApiClient,
    /// How long to wait for processes to die and cgroups to empty.
    cleanup_wait: Duration,
    /// False once torn down.
    live: bool,
}

impl Jail {
    pub async fn create(
        paths: JailPaths,
        api_timeout: Duration,
        cleanup_wait: Duration,
    ) -> Result<Self, RuntimeError> {
        let leftover_pid = read_pid(&paths.pid_file).await;
        if leftover_pid.is_some() || paths.jail_dir.exists() || paths.cgroup.exists() {
            tracing::warn!(jail = %paths.id, "removing a leftover jail with the same id");
        }
        run_cleanup(&cleanup_plan(&paths, leftover_pid), cleanup_wait)
            .await
            .map_err(|e| {
                RuntimeError::Failed(format!("clearing leftover jail {}: {e}", paths.id))
            })?;
        tokio::fs::create_dir_all(&paths.root).await?;
        let api = ApiClient::new(paths.api_socket.clone(), api_timeout);
        Ok(Self {
            paths,
            pid: None,
            console: ConsoleLog::new(CONSOLE_CAPACITY),
            readers: Vec::new(),
            api,
            cleanup_wait,
            live: true,
        })
    }

    pub fn paths(&self) -> &JailPaths {
        &self.paths
    }

    pub fn api(&self) -> &ApiClient {
        &self.api
    }

    /// Runs the jailer and waits until Firecracker's API socket accepts
    /// connections.
    pub async fn launch(
        &mut self,
        jailer: &Path,
        args: &[String],
        within: Duration,
    ) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + within;
        let mut child = Command::new(jailer)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                RuntimeError::Failed(format!("starting the jailer {}: {e}", jailer.display()))
            })?;
        if let Some(out) = child.stdout.take() {
            self.readers.push(self.console.capture(out));
        }
        if let Some(err) = child.stderr.take() {
            self.readers.push(self.console.capture(err));
        }

        // With --new-pid-ns the jailer exits as soon as Firecracker is
        // running in its PID namespace.
        let status = match tokio::time::timeout(within, child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                return Err(self.failure(format!("the jailer did not finish within {within:?}")))
            }
        };
        if !status.success() {
            self.drain_readers(Duration::from_millis(250)).await;
            return Err(self.failure(format!("the jailer failed ({status})")));
        }
        let pid = read_pid(&self.paths.pid_file).await.ok_or_else(|| {
            self.failure(format!(
                "the jailer left no PID in {}",
                self.paths.pid_file.display()
            ))
        })?;
        self.pid = Some(pid);

        loop {
            if UnixStream::connect(&self.paths.api_socket).await.is_ok() {
                break;
            }
            if !self.is_running() {
                // Its output ends with the reason; wait for the pipe to close.
                self.drain_readers(Duration::from_millis(250)).await;
                return Err(self.failure("Firecracker exited during startup".into()));
            }
            if Instant::now() >= deadline {
                return Err(self.failure(format!(
                    "Firecracker's API socket did not appear within {within:?}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tracing::debug!(jail = %self.paths.id, pid, "firecracker is up");
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        cgroup_populated(&self.paths.cgroup)
            || self.pid.is_some_and(|pid| vmm_alive(pid, &self.paths.id))
    }

    /// Resolves once the VMM has exited (a guest panic or reboot ends it).
    pub async fn exited(&self) {
        while self.is_running() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// An error carrying the end of the VMM's console output.
    pub fn failure(&self, what: String) -> RuntimeError {
        let tail = self.console.tail(ERROR_TAIL);
        if tail.is_empty() {
            RuntimeError::Failed(what)
        } else {
            RuntimeError::Failed(format!("{what}; VMM output:\n{tail}"))
        }
    }

    /// Kills the VMM and waits until it has exited, keeping the chroot so
    /// the files it wrote can be taken out.
    pub async fn kill(&mut self) -> Result<(), RuntimeError> {
        let pid = self.known_pid().await;
        run_cleanup(&kill_plan(&self.paths, pid), self.cleanup_wait)
            .await
            .map_err(|e| RuntimeError::Failed(format!("stopping VMM {}: {e}", self.paths.id)))
    }

    /// Kills the VMM and removes the chroot and the cgroup. Idempotent.
    pub async fn destroy(mut self) -> Result<(), RuntimeError> {
        let pid = self.known_pid().await;
        let result = run_cleanup(&cleanup_plan(&self.paths, pid), self.cleanup_wait).await;
        self.live = false;
        for r in self.readers.drain(..) {
            r.abort();
        }
        result.map_err(|e| RuntimeError::Failed(format!("removing jail {}: {e}", self.paths.id)))
    }

    /// The VMM's PID, also when `launch` gave up before recording it (the
    /// jailer may have started Firecracker after all).
    async fn known_pid(&self) -> Option<i32> {
        match self.pid {
            Some(pid) => Some(pid),
            None => read_pid(&self.paths.pid_file).await,
        }
    }

    async fn drain_readers(&mut self, within: Duration) {
        let readers: Vec<_> = self.readers.drain(..).collect();
        let _ = tokio::time::timeout(within, async {
            for r in readers {
                let _ = r.await;
            }
        })
        .await;
    }
}

impl Drop for Jail {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        tracing::warn!(jail = %self.paths.id, "jail dropped without teardown; killing its VMM");
        // Stop the guest now; remove the files when the runtime gets to it.
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .open(self.paths.cgroup.join("cgroup.kill"))
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(b"1")
            });
        let plan = cleanup_plan(&self.paths, self.pid);
        let wait = self.cleanup_wait;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = run_cleanup(&plan, wait).await;
            });
        }
    }
}

async fn read_pid(pid_file: &Path) -> Option<i32> {
    tokio::fs::read_to_string(pid_file)
        .await
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::super::api::fake::FakeFirecracker;
    use super::super::jail::JailPaths;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Stands in for the jailer: starts a long-lived "Firecracker" (a shell
    /// with `--id <id>` on its command line, blocked on a FIFO nobody
    /// writes) that inherits stdout, writes the PID file and exits.
    const FAKE_JAILER: &str = r#"#!/bin/sh
set -eu
while [ $# -gt 0 ]; do
  case "$1" in
    --id) id="$2"; shift 2 ;;
    --chroot-base-dir) base="$2"; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
root="$base/firecracker/$id/root"
echo "jailer: starting $id"
if [ "$id" = "broken" ]; then echo "jailer: Failed to join network namespace" >&2; exit 1; fi
mkfifo "$root/hold"
sh -c 'echo "[    0.000000] Linux version 6.18.54-weft"; read -r _ < "$0"' "$root/hold" --id "$id" &
echo $! > "$root/firecracker.pid"
"#;

    fn setup(dir: &Path, id: &str) -> (JailPaths, std::path::PathBuf) {
        let jailer = dir.join("jailer");
        std::fs::write(&jailer, FAKE_JAILER).unwrap();
        std::fs::set_permissions(&jailer, std::fs::Permissions::from_mode(0o755)).unwrap();
        let paths = JailPaths::new(
            &dir.join("jail"),
            Path::new("/usr/bin/firecracker"),
            &dir.join("cgroup"),
            "firecracker",
            id,
        )
        .unwrap();
        (paths, jailer)
    }

    fn args(paths: &JailPaths, dir: &Path) -> Vec<String> {
        [
            "--id",
            &paths.id,
            "--chroot-base-dir",
            &dir.join("jail").display().to_string(),
            "--",
            "--api-sock",
            "x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[tokio::test]
    async fn launches_captures_output_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, jailer) = setup(dir.path(), "sb1");
        std::fs::create_dir_all(paths.jail_dir.join("leftover")).unwrap();
        let mut jail = Jail::create(
            paths.clone(),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(
            !paths.jail_dir.join("leftover").exists(),
            "leftovers are cleared"
        );
        assert!(paths.root.is_dir());

        std::fs::create_dir_all(paths.root.join("run")).unwrap();
        let fc = FakeFirecracker::serve(&paths.api_socket, vec![]);
        jail.launch(&jailer, &args(&paths, dir.path()), Duration::from_secs(5))
            .await
            .unwrap();
        let pid = jail.pid.unwrap();
        assert!(jail.is_running());
        jail.api()
            .put("/vm", &serde_json::json!({"state": "Paused"}))
            .await
            .unwrap();
        assert_eq!(fc.paths(), ["PUT /vm"]);

        // Output from both the jailer and "Firecracker" lands in the ring.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !jail.console.tail(4096).contains("Linux version") && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let tail = jail.failure("x".into()).to_string();
        assert!(
            tail.contains("jailer: starting sb1") && tail.contains("Linux version 6.18.54-weft"),
            "{tail}"
        );

        jail.destroy().await.unwrap();
        assert!(!vmm_alive(pid, "sb1"), "VMM killed");
        assert!(!paths.jail_dir.exists());
    }

    #[tokio::test]
    async fn reports_jailer_failures_with_its_output() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, jailer) = setup(dir.path(), "broken");
        let mut jail = Jail::create(
            paths.clone(),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let err = jail
            .launch(&jailer, &args(&paths, dir.path()), Duration::from_secs(5))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("the jailer failed") && msg.contains("Failed to join network namespace"),
            "{msg}"
        );
        jail.destroy().await.unwrap();
        assert!(!paths.jail_dir.exists());
    }

    #[tokio::test]
    async fn notices_a_vmm_that_never_serves_its_api() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, jailer) = setup(dir.path(), "sb2");
        let mut jail = Jail::create(
            paths.clone(),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let err = jail
            .launch(
                &jailer,
                &args(&paths, dir.path()),
                Duration::from_millis(300),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("API socket did not appear"),
            "{err}"
        );
        let pid = jail.pid.unwrap();
        drop(jail);
        // The background cleanup of a dropped jail kills the VMM.
        let deadline = Instant::now() + Duration::from_secs(5);
        while (vmm_alive(pid, "sb2") || paths.jail_dir.exists()) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!vmm_alive(pid, "sb2"));
        assert!(!paths.jail_dir.exists());
    }
}
