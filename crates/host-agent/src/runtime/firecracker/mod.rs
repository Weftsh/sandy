//! Production runtime: one Firecracker microVM per sandbox, always started
//! through the jailer.

use std::path::{Path, PathBuf};

use super::{Result, RuntimeError, SnapshotFiles, StartSpec};
use crate::api_types::BuildTemplateRequest;
use crate::net::{GuestLink, Slot};

/// Settings for the Firecracker runtime.
#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    /// Uncompressed guest kernel (vmlinux).
    pub kernel: PathBuf,
    /// Jailer chroot base, on the same filesystem as `data_dir`.
    pub chroot_base: PathBuf,
    pub data_dir: PathBuf,
    /// First UID/GID for jailed VMMs; slot N runs as `uid_base + N`.
    pub uid_base: u32,
}

pub struct FirecrackerRuntime {
    #[allow(dead_code)]
    cfg: FirecrackerConfig,
}

pub struct FcHandle {
    _private: (),
}

impl FirecrackerRuntime {
    pub fn new(cfg: FirecrackerConfig) -> Result<Self> {
        Ok(Self { cfg })
    }

    pub fn guest_link(&self, slot: &Slot) -> GuestLink {
        let id = self.cfg.uid_base + slot.index;
        GuestLink::Tap { uid: id, gid: id }
    }

    pub async fn finish_template(
        &self,
        _req: &BuildTemplateRequest,
        _build_id: &str,
        _rootfs_dir: &Path,
        _out_dir: &Path,
        _slot: &Slot,
        _log: &(dyn Fn(String) + Send + Sync),
    ) -> Result<()> {
        Err(RuntimeError::Unsupported { runtime: "firecracker", what: "template builds (not implemented yet)" })
    }

    pub async fn start(&self, _spec: StartSpec<'_>) -> Result<FcHandle> {
        Err(RuntimeError::Unsupported { runtime: "firecracker", what: "start (not implemented yet)" })
    }

    pub async fn stop(&self, _h: FcHandle) -> Result<()> {
        Ok(())
    }

    pub async fn pause(&self, _h: FcHandle, _work_dir: &Path) -> Result<SnapshotFiles> {
        Err(RuntimeError::Unsupported { runtime: "firecracker", what: "pause (not implemented yet)" })
    }
}
