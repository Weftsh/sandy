//! Production runtime: one Firecracker microVM per sandbox, always started
//! through the jailer.
//!
//! Targets Firecracker [`FIRECRACKER_VERSION`] (x86_64). Snapshots are only
//! guaranteed to load in the Firecracker release that wrote them, so hosts
//! and templates must move to a new release together.
//!
//! # Lifecycle
//!
//! * **Template build** ([`FirecrackerRuntime::finish_template`]): the
//!   prepared root filesystem becomes a sparse ext4 image, a VM boots it with
//!   `weft-guest-init` as PID 1, the template's start command runs until its
//!   ready command succeeds, and the paused VM is written out as a full
//!   snapshot: `rootfs.ext4`, `memory`, `vmstate`. envd's `/init` is never
//!   called during a build, so every restored sandbox can set its own access
//!   token.
//! * **Start** ([`FirecrackerRuntime::start`]): a fresh jail gets a
//!   copy-on-write clone of the root filesystem image and hard links to the
//!   memory and state files, and Firecracker loads the snapshot with nothing
//!   else configured. Starting from pause snapshot files works the same way.
//!   The manager then sets the clock and access token through envd's `/init`.
//! * **Pause** ([`FirecrackerRuntime::pause`]): full snapshot, VMM stopped,
//!   `rootfs.ext4`, `memory` and `vmstate` moved to the caller's directory.
//! * **Stop**: SIGKILL, then the chroot and the cgroup are removed.
//!
//! Every VM, template or sandbox, sees the same chroot-relative file names,
//! the same tap device (`tap0` in its slot's network namespace) and the same
//! guest addresses, so any jail can restore any snapshot.
//!
//! # Isolation and resources
//!
//! The jailer runs each VMM as UID/GID `uid_base + slot`, chrooted, in a new
//! PID namespace and in the slot's network namespace, with cgroup v2 limits
//! (`memory.max` = guest memory + overhead, `cpu.max` = one CPU per vCPU,
//! `pids.max`) and `RLIMIT_FSIZE`/`RLIMIT_NOFILE`. Network, disk, entropy
//! and console output are rate limited per VM ([`RateLimits`]). The VMM's
//! stdout and stderr, which carry the guest console, go to a 64 KiB ring
//! buffer whose tail is attached to errors.
//!
//! Shared inputs (template memory and state files) are root-owned and
//! read-only for the VMM; only the sandbox's own root filesystem copy is
//! owned by the jail user. Files a VMM wrote are taken out of its chroot
//! only after it is dead, and only if they are regular files.
//!
//! Template and snapshot files are mapped by running VMs: replace them by
//! renaming new files into place, never by rewriting them.
//!
//! # Fresh randomness after restore
//!
//! Many sandboxes resume from one template snapshot, so they start with the
//! same kernel CRNG state (see Firecracker's
//! `docs/snapshotting/random-for-clones.md`). Firecracker always attaches a
//! VMGenID device and changes its identifier on every restore, before the
//! vCPUs run; a guest kernel with `CONFIG_VMGENID` (Linux 5.18+, exposed
//! through ACPI on x86_64) reseeds its CRNG when it handles the change. The
//! virtio-rng entropy device (`CONFIG_HW_RANDOM_VIRTIO`) is attached to every
//! template VM and is part of its snapshot, so restored guests keep drawing
//! host entropy. `guest/kernel/` builds a kernel with both. What the kernel
//! cannot refresh stays shared by all clones of a template: userspace PRNG
//! state in processes started by the template's start command, and
//! `/proc/sys/kernel/random/boot_id`.
//!
//! # Host requirements
//!
//! `/dev/kvm`, cgroup v2, a Firecracker and jailer of the targeted release,
//! the guest kernel from `guest/kernel/build.sh`, a UID/GID range starting at
//! `uid_base` reserved for jails, and the chroot base on the same filesystem
//! as the data directory. Production hosts format that filesystem as XFS with
//! reflink so starting a sandbox clones its root filesystem in constant time
//! (see [`disk`]).

mod api;
mod console;
mod disk;
mod jail;
pub mod model;
mod vm;
mod vmm;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use self::disk::CopyKind;
use self::jail::{in_jail, JailPaths, JailerCommand, VmLimits};
use self::model::RateLimits;
use self::vmm::Jail;
use super::{Result, RuntimeError, SnapshotFiles, StartSpec};
use crate::api_types::BuildTemplateRequest;
use crate::cmd::{Runner, SystemRunner};
use crate::envd::{EnvdClient, ENVD_PORT};
use crate::net::{GuestLink, Slot};

/// The Firecracker release this runtime targets (API, jailer behavior,
/// snapshot format). `guest/kernel/VERSION` pins the same release.
pub const FIRECRACKER_VERSION: &str = "1.17.0";

/// How long to wait for a killed VMM to exit and its cgroup to empty.
const CLEANUP_WAIT: Duration = Duration::from_secs(10);
/// Limit on one envd command during a template build.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause between runs of a template's ready command.
const READY_INTERVAL: Duration = Duration::from_secs(1);
/// Firecracker's vCPU limit.
const MAX_VCPUS: u32 = 32;
const MIN_MEMORY_MIB: u32 = 128;

/// Settings for the Firecracker runtime.
///
/// The first six fields are required; the rest have defaults, so build it as
/// `FirecrackerConfig { firecracker_bin, ..., uid_base, ..Default::default() }`.
#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    /// Uncompressed guest kernel (vmlinux) from `guest/kernel/build.sh`.
    pub kernel: PathBuf,
    /// Jailer chroot base, on the same filesystem as `data_dir`. Keep it
    /// short: the API socket path in a jail must fit in 107 bytes.
    pub chroot_base: PathBuf,
    pub data_dir: PathBuf,
    /// First UID/GID for jailed VMMs; slot N runs as `uid_base + N`.
    pub uid_base: u32,
    /// Where the cgroup v2 hierarchy is mounted (the jailer finds it through
    /// `/proc/mounts`; this must agree). Default `/sys/fs/cgroup`.
    pub cgroup_root: PathBuf,
    /// Cgroup, relative to `cgroup_root`, under which each VM gets its own
    /// (`--parent-cgroup`). Default `firecracker`.
    pub cgroup_parent: String,
    /// Memory a VM's cgroup may use beyond guest RAM: the VMM, device
    /// buffers and page cache for the VM's disk I/O. Default 128 MiB.
    pub memory_overhead_mib: u32,
    /// cgroup `pids.max` per VM; bounds Firecracker's threads. Default 128.
    pub pids_max: u32,
    /// `RLIMIT_NOFILE` per VMM. Default 1024.
    pub max_open_files: u32,
    /// Per-VM network, disk, entropy and console limits. Set a field to
    /// `None` to disable that limiter.
    pub rate_limits: RateLimits,
    /// Custom CPU template (JSON for Firecracker's `PUT /cpu-config`) applied
    /// when building templates, to present the same CPU features on every
    /// host that restores them. Default none.
    pub cpu_template: Option<PathBuf>,
    /// Firecracker log level (`Error`, `Warning`, `Info`, `Debug`). Its log
    /// goes to the console ring buffer. Default `Warning`.
    pub log_level: String,
    /// Jailer start until Firecracker's API answers. Default 10 s.
    pub vmm_start_timeout: Duration,
    /// Ordinary API calls. Default 10 s.
    pub api_timeout: Duration,
    /// Creating or loading a snapshot, which moves all guest memory to or
    /// from disk. Default 5 min.
    pub snapshot_timeout: Duration,
    /// Template boot until envd answers. Default 60 s.
    pub boot_timeout: Duration,
    /// How long a template's ready command may keep failing. Default 5 min.
    pub ready_timeout: Duration,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
            jailer_bin: PathBuf::from("/usr/local/bin/jailer"),
            kernel: PathBuf::from("/var/lib/weft/guest/vmlinux"),
            chroot_base: PathBuf::from("/var/lib/weft/jail"),
            data_dir: PathBuf::from("/var/lib/weft"),
            uid_base: 200_000,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            cgroup_parent: "firecracker".to_owned(),
            memory_overhead_mib: 128,
            pids_max: 128,
            max_open_files: 1024,
            rate_limits: RateLimits::default(),
            cpu_template: None,
            log_level: "Warning".to_owned(),
            vmm_start_timeout: Duration::from_secs(10),
            api_timeout: Duration::from_secs(10),
            snapshot_timeout: Duration::from_secs(300),
            boot_timeout: Duration::from_secs(60),
            ready_timeout: Duration::from_secs(300),
        }
    }
}

pub struct FirecrackerRuntime {
    /// Boxed: the runtime lives in an enum next to much smaller variants.
    cfg: Box<FirecrackerConfig>,
    cpu_template: Option<Vec<u8>>,
    envd: EnvdClient,
    reflink_warned: AtomicBool,
}

/// A running sandbox VM. Dropping it without [`FirecrackerRuntime::stop`]
/// kills the VM and cleans up in the background.
pub struct FcHandle {
    jail: Jail,
}

impl FirecrackerRuntime {
    /// Checks the host and the configuration.
    pub fn new(cfg: FirecrackerConfig) -> Result<Self> {
        if cfg.uid_base == 0 {
            return Err(failed(
                "uid_base must not be 0: jailed VMMs never run as root",
            ));
        }
        jail::exec_name(&cfg.firecracker_bin).map_err(failed)?;
        for (what, path) in [
            ("Firecracker binary", &cfg.firecracker_bin),
            ("jailer binary", &cfg.jailer_bin),
            ("guest kernel", &cfg.kernel),
        ] {
            if !path.is_file() {
                return Err(failed(format!("{what} {} not found", path.display())));
            }
        }
        if !Path::new("/dev/kvm").exists() {
            return Err(failed(
                "/dev/kvm is missing: the Firecracker runtime needs KVM (a .metal instance or nested virtualization)",
            ));
        }
        if !cfg.cgroup_root.join("cgroup.controllers").is_file() {
            return Err(failed(format!(
                "no cgroup v2 hierarchy at {}",
                cfg.cgroup_root.display()
            )));
        }
        std::fs::create_dir_all(&cfg.chroot_base)?;
        if matches!(
            disk::same_filesystem(&cfg.chroot_base, &cfg.data_dir),
            Ok(false)
        ) {
            tracing::warn!(
                chroot_base = %cfg.chroot_base.display(),
                data_dir = %cfg.data_dir.display(),
                "the jail chroots are not on the data filesystem; snapshot files will be copied instead of hard-linked"
            );
        }
        let cpu_template = match &cfg.cpu_template {
            Some(path) => {
                let raw = std::fs::read(path)
                    .map_err(|e| failed(format!("reading CPU template {}: {e}", path.display())))?;
                serde_json::from_slice::<serde_json::Value>(&raw).map_err(|e| {
                    failed(format!("CPU template {} is not JSON: {e}", path.display()))
                })?;
                Some(raw)
            }
            None => None,
        };
        check_firecracker_version(&cfg.firecracker_bin);
        Ok(Self {
            cfg: Box::new(cfg),
            cpu_template,
            envd: EnvdClient::new(),
            reflink_warned: AtomicBool::new(false),
        })
    }

    pub fn guest_link(&self, slot: &Slot) -> GuestLink {
        let id = self.cfg.uid_base + slot.index;
        GuestLink::Tap { uid: id, gid: id }
    }

    /// Builds the template's snapshot from a prepared root filesystem and
    /// leaves `rootfs.ext4`, `memory` and `vmstate` in `out_dir`. `slot` has
    /// been set up for [`Self::guest_link`].
    pub async fn finish_template(
        &self,
        req: &BuildTemplateRequest,
        build_id: &str,
        rootfs_dir: &Path,
        out_dir: &Path,
        slot: &Slot,
        log: &(dyn Fn(String) + Send + Sync),
    ) -> Result<()> {
        check_machine(req.vcpus, req.memory_mib)?;
        if req.disk_mib == 0 {
            return Err(failed("disk_mib must be positive"));
        }
        let started = Instant::now();
        let out = files_in(out_dir);
        let mut jail = self.new_jail(build_id).await?;
        let result = self
            .build(&mut jail, req, rootfs_dir, &out, slot, log)
            .await;
        let teardown = jail.destroy().await;
        if let Err(e) = result {
            remove_files(&out).await;
            return Err(e);
        }
        teardown?;
        tracing::info!(
            build = build_id,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "template snapshot built"
        );
        log(format!(
            "template snapshot ready after {:.1}s",
            started.elapsed().as_secs_f64()
        ));
        Ok(())
    }

    /// Restores a sandbox from its template, or from pause snapshot files.
    pub async fn start(&self, spec: StartSpec<'_>) -> Result<FcHandle> {
        check_machine(spec.vcpus, spec.memory_mib)?;
        let started = Instant::now();
        let template_files = files_in(&spec.template.dir);
        let files = spec.snapshot.unwrap_or(&template_files);
        let mut jail = self.new_jail(spec.sandbox_id).await?;
        match self.restore_into(&mut jail, &spec, files).await {
            Ok(copy) => {
                tracing::info!(
                    sandbox = spec.sandbox_id,
                    build = %spec.template.build_id,
                    from_pause = spec.snapshot.is_some(),
                    rootfs_copy = ?copy,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "sandbox VM restored"
                );
                Ok(FcHandle { jail })
            }
            Err(e) => {
                if let Err(cleanup) = jail.destroy().await {
                    tracing::warn!(sandbox = spec.sandbox_id, error = %cleanup, "cleanup after a failed start");
                }
                Err(e)
            }
        }
    }

    pub async fn stop(&self, h: FcHandle) -> Result<()> {
        let id = h.jail.paths().id.clone();
        h.jail.destroy().await?;
        tracing::info!(sandbox = %id, "sandbox VM stopped");
        Ok(())
    }

    /// Snapshots the VM, stops it and moves the snapshot and its root
    /// filesystem into `work_dir`. On failure the VM is gone as well.
    pub async fn pause(&self, h: FcHandle, work_dir: &Path) -> Result<SnapshotFiles> {
        let started = Instant::now();
        let mut jail = h.jail;
        let files = files_in(work_dir);
        let result = async {
            vm::snapshot(jail.api(), self.cfg.snapshot_timeout)
                .await
                .map_err(|e| jail.failure(format!("snapshotting: {e}")))?;
            jail.kill().await?;
            take_out(&jail, &files, 0o600).await
        }
        .await;
        let id = jail.paths().id.clone();
        let teardown = jail.destroy().await;
        if let Err(e) = result {
            remove_files(&files).await;
            return Err(e);
        }
        teardown?;
        tracing::info!(sandbox = %id, elapsed_ms = started.elapsed().as_millis() as u64, "sandbox VM paused");
        Ok(files)
    }

    async fn new_jail(&self, id: &str) -> Result<Jail> {
        let paths = JailPaths::new(
            &self.cfg.chroot_base,
            &self.cfg.firecracker_bin,
            &self.cfg.cgroup_root,
            &self.cfg.cgroup_parent,
            id,
        )
        .map_err(failed)?;
        Jail::create(paths, self.cfg.api_timeout, CLEANUP_WAIT).await
    }

    async fn build(
        &self,
        jail: &mut Jail,
        req: &BuildTemplateRequest,
        rootfs_dir: &Path,
        out: &SnapshotFiles,
        slot: &Slot,
        log: &(dyn Fn(String) + Send + Sync),
    ) -> Result<()> {
        let (uid, gid) = self.jail_ids(slot);
        let disk_bytes = u64::from(req.disk_mib) << 20;
        log(format!(
            "creating a {} MiB ext4 root filesystem",
            req.disk_mib
        ));
        let image = jail.paths().host(in_jail::ROOTFS);
        disk::create_sparse(&image, disk_bytes).await?;
        SystemRunner
            .run(&disk::mkfs_cmd(rootfs_dir, &image))
            .await?;
        disk::set_owner_and_mode(&image, uid, gid, 0o600)?;
        let kernel = jail.paths().host(in_jail::KERNEL);
        disk::link_or_copy(&self.cfg.kernel, &kernel).await?;
        disk::ensure_world_readable(&kernel)?;

        log(format!(
            "booting the template VM ({} vCPU, {} MiB)",
            req.vcpus, req.memory_mib
        ));
        self.launch(jail, slot, req.vcpus, req.memory_mib, disk_bytes)
            .await?;
        let boot_args = vm::boot_args();
        let plan = vm::BootPlan {
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            boot_args: &boot_args,
            limits: &self.cfg.rate_limits,
            cpu_template: self.cpu_template.clone(),
        };
        vm::boot(jail.api(), &plan)
            .await
            .map_err(|e| jail.failure(format!("booting: {e}")))?;

        let envd = SocketAddr::new(slot.ns_ip.into(), ENVD_PORT);
        tokio::select! {
            ready = self.envd.wait_healthy(envd, self.cfg.boot_timeout) => {
                ready.map_err(|e| jail.failure(format!("the guest agent did not come up: {e}")))?;
            }
            () = jail.exited() => return Err(jail.failure("the template VM stopped while booting".into())),
        }
        log("guest agent is up".into());

        if let Some(start_cmd) = req.start_cmd.as_deref().filter(|c| !c.trim().is_empty()) {
            log(format!("starting: {start_cmd}"));
            let cmd = vm::start_command(start_cmd, &req.env_vars).map_err(RuntimeError::Failed)?;
            let code = self
                .envd
                .run(envd, None, "root", &cmd, COMMAND_TIMEOUT)
                .await
                .map_err(|e| jail.failure(format!("launching the start command: {e}")))?;
            if code != 0 {
                return Err(failed(format!(
                    "the start command could not be launched (exit code {code})"
                )));
            }
        }
        if let Some(ready_cmd) = req.ready_cmd.as_deref().filter(|c| !c.trim().is_empty()) {
            self.wait_ready(jail, envd, ready_cmd, &req.env_vars, log)
                .await?;
        }

        log("snapshotting the template VM".into());
        vm::snapshot(jail.api(), self.cfg.snapshot_timeout)
            .await
            .map_err(|e| jail.failure(format!("snapshotting: {e}")))?;
        jail.kill().await?;
        take_out(jail, out, 0o644).await
    }

    /// Runs the ready command until it exits 0.
    async fn wait_ready(
        &self,
        jail: &Jail,
        envd: SocketAddr,
        ready_cmd: &str,
        env: &BTreeMap<String, String>,
        log: &(dyn Fn(String) + Send + Sync),
    ) -> Result<()> {
        log(format!("waiting for: {ready_cmd}"));
        let cmd = vm::ready_command(ready_cmd, env).map_err(RuntimeError::Failed)?;
        let deadline = Instant::now() + self.cfg.ready_timeout;
        let mut attempt = 0u32;
        loop {
            attempt = attempt.saturating_add(1);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let last = match self
                .envd
                .run(envd, None, "root", &cmd, remaining.min(COMMAND_TIMEOUT))
                .await
            {
                Ok(0) => {
                    log(format!("ready after {attempt} attempt(s)"));
                    return Ok(());
                }
                Ok(code) => format!("exit code {code}"),
                Err(e) => e.to_string(),
            };
            if !jail.is_running() {
                return Err(jail.failure(
                    "the template VM stopped while waiting for the ready command".into(),
                ));
            }
            if Instant::now() + READY_INTERVAL >= deadline {
                return Err(failed(format!(
                    "the ready command did not succeed within {:?} (last attempt: {last})",
                    self.cfg.ready_timeout
                )));
            }
            if attempt == 1 || attempt % 15 == 0 {
                log(format!("not ready yet ({last})"));
            }
            tokio::time::sleep(READY_INTERVAL).await;
        }
    }

    async fn restore_into(
        &self,
        jail: &mut Jail,
        spec: &StartSpec<'_>,
        files: &SnapshotFiles,
    ) -> Result<CopyKind> {
        let (uid, gid) = self.jail_ids(spec.slot);
        let disk_bytes = tokio::fs::metadata(&files.rootfs)
            .await
            .map_err(|e| failed(format!("root filesystem {}: {e}", files.rootfs.display())))?
            .len();
        let rootfs = jail.paths().host(in_jail::ROOTFS);
        let copy = disk::cow_copy(&files.rootfs, &rootfs).await?;
        if copy == CopyKind::Sparse && !self.reflink_warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                chroot_base = %self.cfg.chroot_base.display(),
                "the data filesystem cannot clone files (reflink); every sandbox start copies its whole root \
                 filesystem image. Format it as XFS with reflink=1."
            );
        }
        disk::set_owner_and_mode(&rootfs, uid, gid, 0o600)?;
        for (src, name) in [
            (&files.memory, in_jail::MEMORY),
            (&files.vmstate, in_jail::VMSTATE),
        ] {
            let dst = jail.paths().host(name);
            disk::link_or_copy(src, &dst)
                .await
                .map_err(|e| failed(format!("placing {} in the jail: {e}", src.display())))?;
            disk::ensure_world_readable(&dst)?;
        }
        self.launch(jail, spec.slot, spec.vcpus, spec.memory_mib, disk_bytes)
            .await?;
        vm::restore(jail.api(), &self.cfg.rate_limits, self.cfg.snapshot_timeout)
            .await
            .map_err(|e| jail.failure(format!("restoring: {e}")))?;
        Ok(copy)
    }

    async fn launch(
        &self,
        jail: &mut Jail,
        slot: &Slot,
        vcpus: u32,
        memory_mib: u32,
        disk_bytes: u64,
    ) -> Result<()> {
        let (uid, gid) = self.jail_ids(slot);
        let args = JailerCommand {
            paths: jail.paths(),
            firecracker_bin: &self.cfg.firecracker_bin,
            chroot_base: &self.cfg.chroot_base,
            uid,
            gid,
            netns: &slot.netns,
            cgroup_parent: &self.cfg.cgroup_parent,
            limits: vm_limits(&self.cfg, vcpus, memory_mib, disk_bytes),
            log_level: &self.cfg.log_level,
        }
        .args();
        jail.launch(&self.cfg.jailer_bin, &args, self.cfg.vmm_start_timeout)
            .await
    }

    /// Same IDs as [`Self::guest_link`]: the jail user owns the slot's tap.
    fn jail_ids(&self, slot: &Slot) -> (u32, u32) {
        let id = self.cfg.uid_base + slot.index;
        (id, id)
    }
}

fn vm_limits(cfg: &FirecrackerConfig, vcpus: u32, memory_mib: u32, disk_bytes: u64) -> VmLimits {
    let memory = u64::from(memory_mib) << 20;
    VmLimits {
        vcpus,
        memory_max_bytes: memory + (u64::from(cfg.memory_overhead_mib) << 20),
        pids_max: cfg.pids_max,
        // The largest files a VMM writes: its root filesystem image (in
        // place) and a full memory snapshot.
        fsize_bytes: memory.max(disk_bytes) + (64 << 20),
        no_file: cfg.max_open_files,
    }
}

fn check_machine(vcpus: u32, memory_mib: u32) -> Result<()> {
    if !(1..=MAX_VCPUS).contains(&vcpus) {
        return Err(failed(format!(
            "{vcpus} vCPUs requested; Firecracker supports 1 to {MAX_VCPUS}"
        )));
    }
    if memory_mib < MIN_MEMORY_MIB {
        return Err(failed(format!(
            "{memory_mib} MiB of memory requested; the minimum is {MIN_MEMORY_MIB} MiB"
        )));
    }
    Ok(())
}

/// The runtime's file names in a template, output or work directory.
fn files_in(dir: &Path) -> SnapshotFiles {
    SnapshotFiles {
        rootfs: dir.join("rootfs.ext4"),
        memory: dir.join("memory"),
        vmstate: dir.join("vmstate"),
    }
}

/// Moves a dead VMM's root filesystem and snapshot out of its jail, owned by
/// root. `snapshot_mode` applies to the memory and state files.
async fn take_out(jail: &Jail, to: &SnapshotFiles, snapshot_mode: u32) -> Result<()> {
    if let Some(dir) = to.rootfs.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    for (name, dst, mode) in [
        (in_jail::ROOTFS, &to.rootfs, 0o600),
        (in_jail::MEMORY_OUT, &to.memory, snapshot_mode),
        (in_jail::VMSTATE_OUT, &to.vmstate, snapshot_mode),
    ] {
        disk::move_out_of_jail(&jail.paths().host(name), dst)
            .await
            .map_err(|e| failed(format!("taking {name} out of the jail: {e}")))?;
        disk::set_owner_and_mode(dst, 0, 0, mode)?;
    }
    Ok(())
}

async fn remove_files(files: &SnapshotFiles) {
    for f in [&files.rootfs, &files.memory, &files.vmstate] {
        let _ = tokio::fs::remove_file(f).await;
    }
}

fn failed(e: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Failed(e.to_string())
}

/// Logs the installed Firecracker's version and warns when it is not the
/// targeted release: snapshots may not load across releases.
fn check_firecracker_version(bin: &Path) {
    let output = std::process::Command::new(bin)
        .arg("--version")
        .env_clear()
        .output();
    let version = output
        .ok()
        .and_then(|o| parse_version(&String::from_utf8_lossy(&o.stdout)));
    match version {
        Some(v) if same_minor(&v, FIRECRACKER_VERSION) => {
            tracing::info!(version = %v, "using Firecracker")
        }
        Some(v) => tracing::warn!(
            version = %v,
            targeted = FIRECRACKER_VERSION,
            "Firecracker version differs from the one this agent targets; templates built by other versions may not restore"
        ),
        None => tracing::warn!(bin = %bin.display(), "could not determine the Firecracker version"),
    }
}

/// `Firecracker v1.17.0` -> `1.17.0`.
fn parse_version(output: &str) -> Option<String> {
    let line = output.lines().find(|l| l.starts_with("Firecracker v"))?;
    let v = line
        .trim_start_matches("Firecracker v")
        .split_whitespace()
        .next()?;
    let parts: Vec<&str> = v.split('.').collect();
    (parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok())).then(|| v.to_owned())
}

fn same_minor(a: &str, b: &str) -> bool {
    fn minor(v: &str) -> Vec<&str> {
        v.splitn(3, '.').take(2).collect()
    }
    minor(a) == minor(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_usable() {
        let cfg = FirecrackerConfig::default();
        assert!(
            cfg.uid_base > 65_535,
            "jail IDs stay clear of regular accounts"
        );
        assert!(
            cfg.chroot_base.starts_with(&cfg.data_dir),
            "chroots share the data filesystem"
        );
        // Realistic IDs fit the socket path limit with the default base.
        let paths = JailPaths::new(
            &cfg.chroot_base,
            &cfg.firecracker_bin,
            &cfg.cgroup_root,
            &cfg.cgroup_parent,
            "3f2b8c1e-5d6a-4b7c-9e0f-123456789abc",
        );
        assert!(paths.is_ok());
    }

    #[test]
    fn limits_cover_memory_disk_and_overhead() {
        let cfg = FirecrackerConfig::default();
        let l = vm_limits(&cfg, 2, 1024, 4 << 30);
        assert_eq!(l.vcpus, 2);
        assert_eq!(l.memory_max_bytes, (1024 + 128) << 20);
        assert_eq!(
            l.fsize_bytes,
            (4 << 30) + (64 << 20),
            "the disk image is the largest file"
        );
        let l = vm_limits(&cfg, 1, 8192, 1 << 30);
        assert_eq!(
            l.fsize_bytes,
            (8192u64 << 20) + (64 << 20),
            "a memory snapshot is the largest file"
        );
        assert_eq!((l.pids_max, l.no_file), (128, 1024));
    }

    #[test]
    fn validates_machine_sizes() {
        assert!(check_machine(1, 128).is_ok());
        assert!(check_machine(32, 65536).is_ok());
        assert!(check_machine(0, 512).is_err());
        assert!(check_machine(33, 512).is_err());
        assert!(check_machine(2, 64).is_err());
    }

    #[test]
    fn file_names_match_the_template_layout() {
        let f = files_in(Path::new("/var/lib/weft/templates/b1"));
        assert_eq!(
            f.rootfs,
            Path::new("/var/lib/weft/templates/b1/rootfs.ext4")
        );
        assert_eq!(f.memory, Path::new("/var/lib/weft/templates/b1/memory"));
        assert_eq!(f.vmstate, Path::new("/var/lib/weft/templates/b1/vmstate"));
    }

    #[test]
    fn parses_firecracker_versions() {
        let out = "Firecracker v1.17.0\n\nSupported snapshot data format versions: v8.0.0\n";
        assert_eq!(parse_version(out).as_deref(), Some("1.17.0"));
        assert!(same_minor("1.17.3", FIRECRACKER_VERSION));
        assert!(!same_minor("1.16.1", FIRECRACKER_VERSION));
        assert_eq!(parse_version("jailer v1.17.0"), None);
        assert_eq!(parse_version("Firecracker vX"), None);
    }

    #[test]
    fn guest_link_and_jail_ids_agree() {
        let cfg = FirecrackerConfig {
            uid_base: 300_000,
            ..Default::default()
        };
        let rt = FirecrackerRuntime {
            cfg: Box::new(cfg),
            cpu_template: None,
            envd: EnvdClient::new(),
            reflink_warned: AtomicBool::new(false),
        };
        let net = crate::net::NetConfig {
            pool: "10.200.0.0/16".parse().unwrap(),
            dns_port: 1,
            egress_port: 2,
        };
        let slot = Slot::new(&net, 7).unwrap();
        assert_eq!(
            rt.guest_link(&slot),
            GuestLink::Tap {
                uid: 300_007,
                gid: 300_007
            }
        );
        assert_eq!(rt.jail_ids(&slot), (300_007, 300_007));
    }
}
