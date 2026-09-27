//! Sandbox runtimes.
//!
//! * [`firecracker`]: production. One Firecracker microVM per sandbox,
//!   started through the jailer, restored from the template's snapshot.
//! * [`namespace`]: development and CI only. Runs envd in Linux namespaces
//!   on the host kernel with the same network plumbing as Firecracker. It is
//!   **not an isolation boundary** and refuses to start unless explicitly
//!   enabled.
//!
//! The manager owns slots, networking, templates and envd initialization;
//! a runtime only starts, stops, pauses and resumes the guest.

pub mod firecracker;
pub mod namespace;

use std::path::{Path, PathBuf};

use crate::api_types::BuildTemplateRequest;
use crate::net::{GuestLink, Slot};

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("{0}")]
    Failed(String),
    #[error("not supported by the {runtime} runtime: {what}")]
    Unsupported { runtime: &'static str, what: &'static str },
    #[error(transparent)]
    Cmd(#[from] crate::cmd::CmdError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

/// A template as cached on this host.
#[derive(Clone, Debug)]
pub struct LocalTemplate {
    pub build_id: String,
    /// Directory holding the runtime's template files:
    /// namespace: `rootfs/` (a directory);
    /// firecracker: `rootfs.ext4`, `memory`, `vmstate`.
    pub dir: PathBuf,
}

/// Files a Firecracker pause produced, ready to upload.
#[derive(Clone, Debug)]
pub struct SnapshotFiles {
    pub rootfs: PathBuf,
    pub memory: PathBuf,
    pub vmstate: PathBuf,
}

/// Everything a runtime needs to start one guest.
pub struct StartSpec<'a> {
    pub sandbox_id: &'a str,
    pub slot: &'a Slot,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub template: &'a LocalTemplate,
    /// Resume from these snapshot files (Firecracker) instead of the template.
    pub snapshot: Option<&'a SnapshotFiles>,
}

pub enum Runtime {
    Namespace(namespace::NamespaceRuntime),
    Firecracker(firecracker::FirecrackerRuntime),
}

pub enum Handle {
    Namespace(namespace::NsHandle),
    Firecracker(firecracker::FcHandle),
}

/// Result of pausing a guest.
pub enum Paused {
    /// The guest is frozen in place; resume with [`Runtime::thaw`].
    Frozen(Handle),
    /// The guest was snapshotted and stopped.
    Snapshot(SnapshotFiles),
}

impl Runtime {
    pub fn name(&self) -> &'static str {
        match self {
            Runtime::Namespace(_) => "namespace",
            Runtime::Firecracker(_) => "firecracker",
        }
    }

    /// Removes guests a previous agent process left running.
    pub async fn cleanup_leftovers(&self) {
        if let Runtime::Namespace(r) = self {
            r.cleanup_leftovers().await;
        }
    }

    /// How the guest attaches to its slot namespace.
    pub fn guest_link(&self, slot: &Slot) -> GuestLink {
        match self {
            Runtime::Namespace(r) => r.guest_link(slot),
            Runtime::Firecracker(r) => r.guest_link(slot),
        }
    }

    /// Whether `/init` may set the guest clock. Only true for microVMs, whose
    /// clock is their own.
    pub fn sets_guest_clock(&self) -> bool {
        matches!(self, Runtime::Firecracker(_))
    }

    /// Finishes a template whose root filesystem has been unpacked and
    /// prepared in `rootfs_dir`. Firecracker boots it once and snapshots it;
    /// the namespace runtime just keeps the directory.
    pub async fn finish_template(
        &self,
        req: &BuildTemplateRequest,
        build_id: &str,
        rootfs_dir: &Path,
        out_dir: &Path,
        slot: &Slot,
        log: &(dyn Fn(String) + Send + Sync),
    ) -> Result<()> {
        match self {
            Runtime::Namespace(r) => r.finish_template(rootfs_dir, out_dir).await,
            Runtime::Firecracker(r) => r.finish_template(req, build_id, rootfs_dir, out_dir, slot, log).await,
        }
    }

    pub async fn start(&self, spec: StartSpec<'_>) -> Result<Handle> {
        match self {
            Runtime::Namespace(r) => r.start(spec).await.map(Handle::Namespace),
            Runtime::Firecracker(r) => r.start(spec).await.map(Handle::Firecracker),
        }
    }

    pub async fn stop(&self, handle: Handle) -> Result<()> {
        match (self, handle) {
            (Runtime::Namespace(r), Handle::Namespace(h)) => r.stop(h).await,
            (Runtime::Firecracker(r), Handle::Firecracker(h)) => r.stop(h).await,
            _ => Err(RuntimeError::Failed("handle belongs to another runtime".into())),
        }
    }

    /// Pauses a guest. `work_dir` is where snapshot files may be written.
    pub async fn pause(&self, handle: Handle, work_dir: &Path) -> Result<Paused> {
        match (self, handle) {
            (Runtime::Namespace(r), Handle::Namespace(h)) => r.freeze(&h).await.map(|()| Paused::Frozen(Handle::Namespace(h))),
            (Runtime::Firecracker(r), Handle::Firecracker(h)) => r.pause(h, work_dir).await.map(Paused::Snapshot),
            _ => Err(RuntimeError::Failed("handle belongs to another runtime".into())),
        }
    }

    /// Resumes a guest frozen in place.
    pub async fn thaw(&self, handle: &Handle) -> Result<()> {
        match (self, handle) {
            (Runtime::Namespace(r), Handle::Namespace(h)) => r.thaw(h).await,
            _ => Err(RuntimeError::Unsupported { runtime: self.name(), what: "thawing a frozen guest" }),
        }
    }
}
