//! The jailer's on-disk layout, its command line, and how a jail is torn
//! down.
//!
//! The jailer builds `<chroot_base>/<exec name>/<id>/root`, copies the
//! Firecracker binary into it, puts the process in the cgroup
//! `<cgroup root>/<parent>/<id>`, joins the slot's network namespace, drops
//! to the jail's UID/GID and, with `--new-pid-ns`, execs Firecracker as PID 1
//! of a new PID namespace. The jailer itself exits right away and leaves
//! Firecracker's host PID in `<root>/<exec name>.pid`.
//!
//! Everything the VM needs is placed in the chroot under the same
//! chroot-relative names in every jail ([`in_jail`]), which is what lets any
//! jail restore any snapshot.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// Chroot-relative paths, identical in every jail. Snapshots record the
/// drive path, so these must never change for existing templates.
pub mod in_jail {
    pub const KERNEL: &str = "/vmlinux";
    pub const ROOTFS: &str = "/rootfs.ext4";
    /// Snapshot being restored (hard links to template or pause files).
    pub const MEMORY: &str = "/memory";
    pub const VMSTATE: &str = "/vmstate";
    /// Snapshot being written. Distinct from the inputs: Firecracker
    /// truncates its output files, and the inputs are hard links to files
    /// other VMs map.
    pub const MEMORY_OUT: &str = "/memory.new";
    pub const VMSTATE_OUT: &str = "/vmstate.new";
    pub const API_SOCKET: &str = "/run/firecracker.socket";
}

/// Where network namespace handles live (`ip netns`).
const NETNS_DIR: &str = "/var/run/netns";
/// Unix socket paths are limited to 108 bytes including the terminator.
const MAX_SOCKET_PATH: usize = 107;
/// The jailer's limit on `--id`.
const MAX_ID_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum JailError {
    #[error("invalid jail id {0:?}: use 1-64 ASCII letters, digits and hyphens")]
    InvalidId(String),
    #[error("{0}")]
    Config(String),
    #[error("{what} {}: {source}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

/// Paths of one jail on the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JailPaths {
    pub id: String,
    /// `<chroot_base>/<exec name>/<id>`: removed as a whole on cleanup.
    pub jail_dir: PathBuf,
    /// `<jail_dir>/root`: the VMM's `/`.
    pub root: PathBuf,
    pub api_socket: PathBuf,
    pub pid_file: PathBuf,
    /// `<cgroup root>/<parent>/<id>`, created by the jailer.
    pub cgroup: PathBuf,
}

impl JailPaths {
    pub fn new(
        chroot_base: &Path,
        exec_file: &Path,
        cgroup_root: &Path,
        cgroup_parent: &str,
        id: &str,
    ) -> Result<Self, JailError> {
        validate_id(id)?;
        let exec_name = exec_name(exec_file)?;
        let jail_dir = chroot_base.join(exec_name).join(id);
        let root = jail_dir.join("root");
        let paths = Self {
            id: id.to_owned(),
            api_socket: host_path(&root, in_jail::API_SOCKET),
            pid_file: root.join(format!("{exec_name}.pid")),
            cgroup: cgroup_root.join(cgroup_parent).join(id),
            jail_dir,
            root,
        };
        if paths.api_socket.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(JailError::Config(format!(
                "API socket path {} exceeds {MAX_SOCKET_PATH} bytes; use a shorter chroot base",
                paths.api_socket.display()
            )));
        }
        Ok(paths)
    }

    /// Host path of a chroot-relative path such as [`in_jail::ROOTFS`].
    pub fn host(&self, in_jail: &str) -> PathBuf {
        host_path(&self.root, in_jail)
    }
}

fn host_path(root: &Path, in_jail: &str) -> PathBuf {
    root.join(in_jail.trim_start_matches('/'))
}

/// The jailer names the chroot and PID file after the binary's file name.
pub fn exec_name(exec_file: &Path) -> Result<&str, JailError> {
    exec_file
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| {
            JailError::Config(format!(
                "bad Firecracker binary path {}",
                exec_file.display()
            ))
        })
}

/// Jail IDs become path components and cgroup names; the jailer accepts
/// letters, digits and hyphens, at most 64 of them.
pub fn validate_id(id: &str) -> Result<(), JailError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(JailError::InvalidId(id.to_owned()))
    }
}

/// Resource bounds applied by the jailer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmLimits {
    pub vcpus: u32,
    /// cgroup `memory.max`: guest memory plus VMM overhead.
    pub memory_max_bytes: u64,
    /// cgroup `pids.max`: threads count, so this bounds Firecracker's threads.
    pub pids_max: u32,
    /// `RLIMIT_FSIZE`: must cover the root filesystem image and a full memory
    /// snapshot, the largest files the VMM writes.
    pub fsize_bytes: u64,
    /// `RLIMIT_NOFILE`.
    pub no_file: u32,
}

/// cgroup v2 `cpu.max` period in microseconds.
const CPU_PERIOD_US: u64 = 100_000;

/// Everything on the jailer's command line.
#[derive(Clone, Debug)]
pub struct JailerCommand<'a> {
    pub paths: &'a JailPaths,
    pub firecracker_bin: &'a Path,
    pub chroot_base: &'a Path,
    pub uid: u32,
    pub gid: u32,
    /// Name of the slot's network namespace.
    pub netns: &'a str,
    pub cgroup_parent: &'a str,
    pub limits: VmLimits,
    /// Firecracker's log level (`Error`, `Warning`, `Info`, `Debug`).
    pub log_level: &'a str,
}

impl JailerCommand<'_> {
    pub fn args(&self) -> Vec<String> {
        let l = &self.limits;
        let jailer = [
            ("--id", self.paths.id.clone()),
            ("--exec-file", self.firecracker_bin.display().to_string()),
            ("--uid", self.uid.to_string()),
            ("--gid", self.gid.to_string()),
            ("--chroot-base-dir", self.chroot_base.display().to_string()),
            ("--netns", format!("{NETNS_DIR}/{}", self.netns)),
            ("--cgroup-version", "2".to_owned()),
            ("--parent-cgroup", self.cgroup_parent.to_owned()),
            ("--cgroup", format!("memory.max={}", l.memory_max_bytes)),
            (
                "--cgroup",
                format!(
                    "cpu.max={} {CPU_PERIOD_US}",
                    u64::from(l.vcpus) * CPU_PERIOD_US
                ),
            ),
            ("--cgroup", format!("pids.max={}", l.pids_max)),
            ("--resource-limit", format!("fsize={}", l.fsize_bytes)),
            ("--resource-limit", format!("no-file={}", l.no_file)),
        ];
        let firecracker = [
            ("--api-sock", in_jail::API_SOCKET.to_owned()),
            ("--level", self.log_level.to_owned()),
        ];
        let pairs = |list: &[(&str, String)]| -> Vec<String> {
            list.iter()
                .flat_map(|(flag, value)| [(*flag).to_owned(), value.clone()])
                .collect()
        };
        let mut args = pairs(&jailer);
        args.push("--new-pid-ns".to_owned());
        // Everything after `--` goes to Firecracker.
        args.push("--".to_owned());
        args.extend(pairs(&firecracker));
        args
    }
}

/// One step of tearing a jail down. Every step tolerates its target being
/// gone, so a plan can run any number of times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanupStep {
    /// SIGKILL the VMM, if `pid` is still this jail's Firecracker (checked
    /// through its command line, so a recycled PID is never signalled).
    KillVmm { pid: i32, id: String },
    /// SIGKILL whatever is left in the cgroup and wait until it is empty.
    KillCgroup(PathBuf),
    /// Remove the (empty) cgroup.
    RemoveCgroup(PathBuf),
    /// Remove the jail directory and the chroot in it.
    RemoveDir(PathBuf),
}

/// Stops the VMM and waits until it has exited; leaves the files.
pub fn kill_plan(paths: &JailPaths, pid: Option<i32>) -> Vec<CleanupStep> {
    let mut plan = Vec::with_capacity(4);
    if let Some(pid) = pid {
        plan.push(CleanupStep::KillVmm {
            pid,
            id: paths.id.clone(),
        });
    }
    plan.push(CleanupStep::KillCgroup(paths.cgroup.clone()));
    plan
}

/// Stops the VMM and removes everything the jail consisted of.
pub fn cleanup_plan(paths: &JailPaths, pid: Option<i32>) -> Vec<CleanupStep> {
    let mut plan = kill_plan(paths, pid);
    plan.extend([
        CleanupStep::RemoveCgroup(paths.cgroup.clone()),
        CleanupStep::RemoveDir(paths.jail_dir.clone()),
    ]);
    plan
}

/// Runs every step, even after a failure, and returns the first error.
pub async fn run_cleanup(plan: &[CleanupStep], wait: Duration) -> Result<(), JailError> {
    let mut first_err = None;
    for step in plan {
        if let Err(e) = run_step(step, wait).await {
            tracing::warn!(?step, error = %e, "jail cleanup step failed");
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

async fn run_step(step: &CleanupStep, wait: Duration) -> Result<(), JailError> {
    match step {
        CleanupStep::KillVmm { pid, id } => {
            let deadline = Instant::now() + wait;
            loop {
                match probe(*pid, id) {
                    ProcState::Gone | ProcState::Other => return Ok(()),
                    ProcState::Ours => {
                        let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
                    }
                    // Mid-exec: wait until it shows who it is.
                    ProcState::Exec => {}
                }
                if Instant::now() >= deadline {
                    return Err(JailError::Config(format!(
                        "VMM {pid} did not exit within {wait:?}"
                    )));
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        CleanupStep::KillCgroup(cg) => kill_cgroup(cg, wait).await,
        CleanupStep::RemoveCgroup(cg) => {
            let deadline = Instant::now() + wait;
            loop {
                match tokio::fs::remove_dir(cg).await {
                    Ok(()) => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                    // EBUSY until the last task is fully gone.
                    Err(e)
                        if Instant::now() < deadline
                            && e.raw_os_error() == Some(nix::libc::EBUSY) =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(source) => {
                        return Err(JailError::Io {
                            what: "removing cgroup",
                            path: cg.clone(),
                            source,
                        })
                    }
                }
            }
        }
        CleanupStep::RemoveDir(dir) => match tokio::fs::remove_dir_all(dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(JailError::Io {
                what: "removing jail",
                path: dir.clone(),
                source,
            }),
        },
    }
}

async fn kill_cgroup(cg: &Path, wait: Duration) -> Result<(), JailError> {
    if !cg.is_dir() {
        return Ok(());
    }
    // cgroup.kill (Linux 5.14+) signals every member atomically.
    let killed = std::fs::OpenOptions::new()
        .write(true)
        .open(cg.join("cgroup.kill"))
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(b"1")
        });
    let deadline = Instant::now() + wait;
    loop {
        let procs = std::fs::read_to_string(cg.join("cgroup.procs")).unwrap_or_default();
        let pids: Vec<i32> = procs
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        if pids.is_empty() && !cgroup_populated(cg) {
            return Ok(());
        }
        if killed.is_err() {
            for pid in &pids {
                let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
            }
        }
        if Instant::now() >= deadline {
            return Err(JailError::Config(format!(
                "cgroup {} still populated after {wait:?}",
                cg.display()
            )));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Whether the cgroup still has live processes. A process leaves its cgroup
/// when it exits, before it is reaped, after its file descriptors and
/// mappings are gone.
pub fn cgroup_populated(cg: &Path) -> bool {
    std::fs::read_to_string(cg.join("cgroup.events"))
        .map(|events| events_populated(&events))
        .unwrap_or(false)
}

fn events_populated(events: &str) -> bool {
    events.lines().any(|l| l.trim() == "populated 1")
}

/// What a PID currently is, as far as a jail is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcState {
    /// Exited (a zombie counts) or never existed.
    Gone,
    /// Alive, with this jail's `--id` on its command line.
    Ours,
    /// Alive with an empty command line: in the middle of `execve`, as the
    /// jailer's child is right after the jailer reports its PID.
    Exec,
    /// Some other process (the PID was recycled).
    Other,
}

fn probe(pid: i32, id: &str) -> ProcState {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return ProcState::Gone;
    };
    if matches!(proc_state(&stat), Some('Z' | 'X') | None) {
        return ProcState::Gone;
    }
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Err(_) => ProcState::Gone,
        Ok(cmdline) if cmdline.is_empty() => ProcState::Exec,
        Ok(cmdline) if cmdline_has_id(&cmdline, id) => ProcState::Ours,
        Ok(_) => ProcState::Other,
    }
}

/// Whether `pid` is still the live Firecracker of jail `id` (or about to be).
pub fn vmm_alive(pid: i32, id: &str) -> bool {
    matches!(probe(pid, id), ProcState::Ours | ProcState::Exec)
}

/// The jailer execs Firecracker with `--id <id>`.
fn cmdline_has_id(cmdline: &[u8], id: &str) -> bool {
    let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
    args.windows(2)
        .any(|w| w[0] == b"--id" && w[1] == id.as_bytes())
}

/// State letter from `/proc/<pid>/stat`. The command name may contain
/// spaces and parentheses, so parse from the last `)`.
fn proc_state(stat: &str) -> Option<char> {
    stat[stat.rfind(')')? + 1..].trim_start().chars().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> JailPaths {
        JailPaths::new(
            Path::new("/srv/weft/jail"),
            Path::new("/usr/local/bin/firecracker"),
            Path::new("/sys/fs/cgroup"),
            "firecracker",
            "i7x2k9abcdef",
        )
        .unwrap()
    }

    #[test]
    fn layout_matches_the_jailer() {
        let p = paths();
        assert_eq!(
            p.jail_dir,
            Path::new("/srv/weft/jail/firecracker/i7x2k9abcdef")
        );
        assert_eq!(
            p.root,
            Path::new("/srv/weft/jail/firecracker/i7x2k9abcdef/root")
        );
        assert_eq!(
            p.api_socket,
            Path::new("/srv/weft/jail/firecracker/i7x2k9abcdef/root/run/firecracker.socket")
        );
        assert_eq!(
            p.pid_file,
            Path::new("/srv/weft/jail/firecracker/i7x2k9abcdef/root/firecracker.pid")
        );
        assert_eq!(
            p.cgroup,
            Path::new("/sys/fs/cgroup/firecracker/i7x2k9abcdef")
        );
        assert_eq!(p.host(in_jail::ROOTFS), p.root.join("rootfs.ext4"));
        // The chroot and PID file follow the binary's name.
        let v = JailPaths::new(
            Path::new("/j"),
            Path::new("/opt/firecracker-v1.17.0-x86_64"),
            Path::new("/sys/fs/cgroup"),
            "fc",
            "a",
        )
        .unwrap();
        assert_eq!(
            v.pid_file,
            Path::new("/j/firecracker-v1.17.0-x86_64/a/root/firecracker-v1.17.0-x86_64.pid")
        );
    }

    #[test]
    fn in_jail_paths_are_absolute_and_inputs_differ_from_outputs() {
        for p in [
            in_jail::KERNEL,
            in_jail::ROOTFS,
            in_jail::MEMORY,
            in_jail::VMSTATE,
            in_jail::MEMORY_OUT,
            in_jail::VMSTATE_OUT,
            in_jail::API_SOCKET,
        ] {
            assert!(p.starts_with('/'), "{p}");
        }
        assert_ne!(in_jail::MEMORY, in_jail::MEMORY_OUT);
        assert_ne!(in_jail::VMSTATE, in_jail::VMSTATE_OUT);
    }

    #[test]
    fn rejects_ids_that_are_not_safe_path_components() {
        for bad in ["", "../etc", "a/b", "a b", "a.b", "sb_1", &"x".repeat(65)] {
            assert!(validate_id(bad).is_err(), "{bad:?}");
        }
        for good in [
            "i7x2k9",
            "3f2b8c1e-5d6a-4b7c-9e0f-123456789abc",
            &"x".repeat(64),
        ] {
            assert!(validate_id(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn rejects_socket_paths_the_kernel_cannot_bind() {
        let long_base = format!("/{}", "d".repeat(60));
        let err = JailPaths::new(
            Path::new(&long_base),
            Path::new("/usr/bin/firecracker"),
            Path::new("/sys/fs/cgroup"),
            "firecracker",
            &"x".repeat(40),
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds 107 bytes"), "{err}");
    }

    #[test]
    fn jailer_command_line() {
        let p = paths();
        let cmd = JailerCommand {
            paths: &p,
            firecracker_bin: Path::new("/usr/local/bin/firecracker"),
            chroot_base: Path::new("/srv/weft/jail"),
            uid: 200_007,
            gid: 200_007,
            netns: "weft-s7",
            cgroup_parent: "firecracker",
            limits: VmLimits {
                vcpus: 2,
                memory_max_bytes: 1152 << 20,
                pids_max: 128,
                fsize_bytes: 4 << 30,
                no_file: 1024,
            },
            log_level: "Warning",
        };
        let args = cmd.args();
        let expected: Vec<&str> = vec![
            "--id",
            "i7x2k9abcdef",
            "--exec-file",
            "/usr/local/bin/firecracker",
            "--uid",
            "200007",
            "--gid",
            "200007",
            "--chroot-base-dir",
            "/srv/weft/jail",
            "--netns",
            "/var/run/netns/weft-s7",
            "--cgroup-version",
            "2",
            "--parent-cgroup",
            "firecracker",
            "--cgroup",
            "memory.max=1207959552",
            "--cgroup",
            "cpu.max=200000 100000",
            "--cgroup",
            "pids.max=128",
            "--resource-limit",
            "fsize=4294967296",
            "--resource-limit",
            "no-file=1024",
            "--new-pid-ns",
            "--",
            "--api-sock",
            "/run/firecracker.socket",
            "--level",
            "Warning",
        ];
        assert_eq!(args, expected);
        assert!(
            !args.iter().any(|a| a == "--daemonize"),
            "stdout carries the console; never daemonize"
        );
    }

    #[test]
    fn cleanup_kills_before_removing() {
        let p = paths();
        let plan = cleanup_plan(&p, Some(4242));
        assert_eq!(
            plan,
            vec![
                CleanupStep::KillVmm {
                    pid: 4242,
                    id: "i7x2k9abcdef".into()
                },
                CleanupStep::KillCgroup(p.cgroup.clone()),
                CleanupStep::RemoveCgroup(p.cgroup.clone()),
                CleanupStep::RemoveDir(p.jail_dir.clone()),
            ]
        );
        assert!(!cleanup_plan(&p, None)
            .iter()
            .any(|s| matches!(s, CleanupStep::KillVmm { .. })));
        // Pausing kills first and removes later, after the snapshot is out.
        assert_eq!(kill_plan(&p, Some(4242)), plan[..2]);
        assert!(!kill_plan(&p, None)
            .iter()
            .any(|s| matches!(s, CleanupStep::RemoveDir(_))));
    }

    #[tokio::test]
    async fn cleanup_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let p = JailPaths::new(
            &tmp.path().join("jail"),
            Path::new("/usr/bin/firecracker"),
            &tmp.path().join("cgroup"),
            "firecracker",
            "sb1",
        )
        .unwrap();
        std::fs::create_dir_all(p.root.join("run")).unwrap();
        std::fs::write(p.host(in_jail::ROOTFS), b"disk").unwrap();
        std::fs::create_dir_all(&p.cgroup).unwrap();
        // A PID that is certainly not a Firecracker for this jail.
        let plan = cleanup_plan(&p, Some(std::process::id() as i32));
        run_cleanup(&plan, Duration::from_secs(1)).await.unwrap();
        assert!(!p.jail_dir.exists());
        assert!(!p.cgroup.exists());
        assert!(
            tmp.path().join("jail/firecracker").exists(),
            "only this jail is removed"
        );
        run_cleanup(&plan, Duration::from_secs(1)).await.unwrap();
    }

    #[test]
    fn parses_proc_files() {
        assert_eq!(proc_state("123 (fire cracker) S 1 2 3"), Some('S'));
        assert_eq!(proc_state("123 (a) b) Z 1"), Some('Z'));
        assert_eq!(proc_state("garbage"), None);
        let cmdline = b"/firecracker\0--id\0sb1\0--start-time-us\x00123\0";
        assert!(cmdline_has_id(cmdline, "sb1"));
        assert!(!cmdline_has_id(cmdline, "sb"));
        assert!(!cmdline_has_id(b"/bin/sleep\0sb1\0", "sb1"));
        assert!(events_populated("populated 1\nfrozen 0\n"));
        assert!(!events_populated("populated 0\nfrozen 0\n"));
        assert!(!vmm_alive(std::process::id() as i32, "sb1"));
    }
}
