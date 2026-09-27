//! Sandbox lifecycle on one host: slots, networking, templates, the runtime
//! and envd initialization.
//!
//! Every operation on a sandbox holds that sandbox's lock, so a pause cannot
//! race a stop. A sandbox is reported running only after envd has been
//! initialized with the sandbox's access token; until then the edge proxy
//! cannot reach it.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use weft_netpolicy::{CompiledPolicy, EgressPolicy};

use crate::api_types::*;
use crate::artifacts::Transfer;
use crate::cmd::{run_all, SystemRunner};
use crate::envd::{EnvdClient, InitRequest, ENVD_PORT};
use crate::net::{self, GuestLink, Slot};
use crate::oci::{Credentials, ImageRef, Puller};
use crate::rootfs;
use crate::runtime::{Handle, LocalTemplate, Paused, Runtime, SnapshotFiles, StartSpec};
use crate::slots::{SlotEntry, SlotTable};

const ENVD_READY_TIMEOUT: Duration = Duration::from_secs(60);
const READY_CMD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_BUILD_LOG_LINES: usize = 2000;

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Capacity(String),
    #[error("{0}")]
    Internal(String),
}

impl ManagerError {
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::Capacity(_) => 503,
            Self::Internal(_) => 500,
        }
    }
}

fn internal(e: impl std::fmt::Display) -> ManagerError {
    ManagerError::Internal(e.to_string())
}

pub type Result<T> = std::result::Result<T, ManagerError>;

#[derive(Clone, Debug)]
pub struct ManagerConfig {
    pub host_id: String,
    pub data_dir: PathBuf,
    /// Holds `envd` and `weft-guest-init` for new templates.
    pub guest_dir: PathBuf,
    pub max_vcpus: u32,
    pub max_memory_mib: u32,
}

/// Template metadata kept next to the cached files.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateMeta {
    build_id: String,
    #[serde(default)]
    start_cmd: Option<String>,
    #[serde(default)]
    ready_cmd: Option<String>,
}

struct Sandbox {
    id: String,
    slot: Slot,
    link: GuestLink,
    started_at: String,
    state: Mutex<SandboxState>,
    envd_version: Mutex<Option<String>>,
    op: tokio::sync::Mutex<Option<Handle>>,
}

impl Sandbox {
    fn info(&self) -> SandboxInfo {
        SandboxInfo {
            sandbox_id: self.id.clone(),
            state: *self.state.lock().expect("poisoned"),
            envd_version: self.envd_version.lock().expect("poisoned").clone(),
            started_at: self.started_at.clone(),
        }
    }
    fn set_state(&self, s: SandboxState) {
        *self.state.lock().expect("poisoned") = s;
    }
    fn state(&self) -> SandboxState {
        *self.state.lock().expect("poisoned")
    }
}

pub struct Manager {
    cfg: ManagerConfig,
    runtime: Runtime,
    runner: SystemRunner,
    envd: EnvdClient,
    transfer: Transfer,
    slots: Arc<SlotTable>,
    sandboxes: Mutex<HashMap<String, Arc<Sandbox>>>,
    templates: Mutex<HashMap<String, TemplateMeta>>,
    template_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    builds: Mutex<HashMap<String, Arc<Mutex<BuildStatus>>>>,
}

/// Sandbox, template and build IDs become paths, interface names and
/// hostnames, so they are restricted to a safe alphabet.
pub fn validate_id(kind: &str, id: &str) -> Result<()> {
    let ok = !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok && !id.starts_with('-') {
        Ok(())
    } else {
        Err(ManagerError::BadRequest(format!("invalid {kind} id {id:?}: use 1-64 lowercase letters, digits and dashes")))
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl Manager {
    pub fn new(cfg: ManagerConfig, runtime: Runtime, slots: Arc<SlotTable>) -> Self {
        Self {
            cfg,
            runtime,
            runner: SystemRunner,
            envd: EnvdClient::new(),
            transfer: Transfer::new(),
            slots,
            sandboxes: Mutex::default(),
            templates: Mutex::default(),
            template_locks: Mutex::default(),
            builds: Mutex::default(),
        }
    }

    pub fn runtime_name(&self) -> &'static str {
        self.runtime.name()
    }

    /// Removes leftovers from a previous run and loads cached templates.
    pub async fn recover(&self) -> Result<()> {
        run_all(&self.runner, &net::host_plan(self.slots.net())).await.map_err(internal)?;
        self.runtime.cleanup_leftovers().await;
        // Sandboxes do not survive an agent restart: the control plane sees
        // them missing from the next heartbeat and marks them stopped.
        for index in 0..self.slots.limit() {
            if let Some(slot) = Slot::new(self.slots.net(), index) {
                let link = self.runtime.guest_link(&slot);
                if Path::new("/var/run/netns").join(&slot.netns).exists() {
                    let _ = run_all(&self.runner, &net::teardown_plan(&slot, &link)).await;
                }
            }
        }
        let sandboxes = self.cfg.data_dir.join("sandboxes");
        if let Ok(mut rd) = tokio::fs::read_dir(&sandboxes).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let _ = nix::mount::umount2(&e.path().join("rootfs"), nix::mount::MntFlags::MNT_DETACH);
            }
        }
        let _ = tokio::fs::remove_dir_all(&sandboxes).await;
        let _ = tokio::fs::remove_dir_all(self.cfg.data_dir.join("builds")).await;

        let dir = self.cfg.data_dir.join("templates");
        tokio::fs::create_dir_all(&dir).await.map_err(internal)?;
        let mut rd = tokio::fs::read_dir(&dir).await.map_err(internal)?;
        while let Ok(Some(e)) = rd.next_entry().await {
            let meta_path = e.path().join("template.json");
            match tokio::fs::read(&meta_path).await.ok().and_then(|b| serde_json::from_slice::<TemplateMeta>(&b).ok()) {
                Some(meta) => {
                    self.templates.lock().expect("poisoned").insert(meta.build_id.clone(), meta);
                }
                None => {
                    // An interrupted build or download.
                    let _ = tokio::fs::remove_dir_all(e.path()).await;
                }
            }
        }
        Ok(())
    }

    // ---- sandboxes ---------------------------------------------------------

    pub async fn start(&self, id: &str, req: StartSandboxRequest) -> Result<SandboxInfo> {
        validate_id("sandbox", id)?;
        validate_id("build", &req.build_id)?;
        if req.vcpus == 0 || req.vcpus > self.cfg.max_vcpus {
            return Err(ManagerError::BadRequest(format!("vcpus must be 1-{}", self.cfg.max_vcpus)));
        }
        if req.memory_mib < 128 || req.memory_mib > self.cfg.max_memory_mib {
            return Err(ManagerError::BadRequest(format!("memoryMib must be 128-{}", self.cfg.max_memory_mib)));
        }
        if req.envd_access_token.len() < 16 {
            return Err(ManagerError::BadRequest("envdAccessToken is too short".into()));
        }
        let policy = Arc::new(CompiledPolicy::compile(&req.egress).map_err(|e| ManagerError::BadRequest(e.to_string()))?);

        let existing = self.sandboxes.lock().expect("poisoned").get(id).cloned();
        if let Some(sb) = existing {
            return self.resume_existing(&sb, &req).await;
        }

        let template = self.ensure_template(&req.build_id, req.template_artifacts.as_ref()).await?;
        let slot = self.slots.reserve().ok_or_else(|| ManagerError::Capacity("host is full".into()))?;
        let link = self.runtime.guest_link(&slot);
        let sb = Arc::new(Sandbox {
            id: id.to_owned(),
            slot: slot.clone(),
            link: link.clone(),
            started_at: now_rfc3339(),
            state: Mutex::new(SandboxState::Starting),
            envd_version: Mutex::new(None),
            op: tokio::sync::Mutex::new(None),
        });
        {
            let mut map = self.sandboxes.lock().expect("poisoned");
            if map.contains_key(id) {
                self.slots.release(slot.index);
                return Err(ManagerError::Conflict("sandbox is already starting".into()));
            }
            map.insert(id.to_owned(), sb.clone());
        }
        let mut guard = sb.op.lock().await;
        match self.boot(&sb, &req, &template, policy).await {
            Ok((handle, version)) => {
                *guard = Some(handle);
                *sb.envd_version.lock().expect("poisoned") = Some(version);
                sb.set_state(SandboxState::Running);
                Ok(sb.info())
            }
            Err(e) => {
                tracing::warn!(sandbox = %id, error = %e, "start failed");
                drop(guard);
                self.remove(id).await;
                Err(e)
            }
        }
    }

    /// Sets up networking, starts the guest (from the template or a pause
    /// snapshot) and initializes envd.
    async fn boot(
        &self,
        sb: &Sandbox,
        req: &StartSandboxRequest,
        template: &LocalTemplate,
        policy: Arc<CompiledPolicy>,
    ) -> Result<(Handle, String)> {
        run_all(&self.runner, &net::teardown_plan(&sb.slot, &sb.link)).await.map_err(internal)?;
        run_all(&self.runner, &net::setup_plan(self.slots.net(), &sb.slot, &sb.link)).await.map_err(internal)?;
        self.slots.occupy(sb.slot.index, SlotEntry { sandbox_id: sb.id.clone(), policy });

        let snapshot = match &req.resume {
            Some(ResumeSource::Remote { snapshot }) => Some(self.download_snapshot(&sb.id, snapshot).await?),
            Some(ResumeSource::Local) => {
                return Err(ManagerError::NotFound("paused sandbox is not on this host".into()));
            }
            None => None,
        };
        let handle = self
            .runtime
            .start(StartSpec {
                sandbox_id: &sb.id,
                slot: &sb.slot,
                vcpus: req.vcpus,
                memory_mib: req.memory_mib,
                template,
                snapshot: snapshot.as_ref(),
            })
            .await
            .map_err(internal)?;
        let version = match self.init_envd(sb, req).await {
            Ok(v) => v,
            Err(e) => {
                let _ = self.runtime.stop(handle).await;
                return Err(e);
            }
        };
        if req.resume.is_none() {
            if let Err(e) = self.run_template_commands(sb, req, template).await {
                let _ = self.runtime.stop(handle).await;
                return Err(e);
            }
        }
        Ok((handle, version))
    }

    async fn init_envd(&self, sb: &Sandbox, req: &StartSandboxRequest) -> Result<String> {
        let addr = SocketAddr::new(sb.slot.ns_ip.into(), ENVD_PORT);
        self.envd.wait_healthy(addr, ENVD_READY_TIMEOUT).await.map_err(internal)?;
        let mut env_vars: BTreeMap<String, String> = req.env_vars.clone();
        env_vars.insert("E2B_SANDBOX_ID".into(), sb.id.clone());
        env_vars.insert("E2B_TEMPLATE_ID".into(), req.template_id.clone());
        env_vars.insert("WEFT_SANDBOX_ID".into(), sb.id.clone());
        if req.ca_bundle.is_some() {
            // Runtimes that ignore the system store still trust the egress CA.
            let bundle = "/etc/ssl/certs/ca-certificates.crt".to_owned();
            env_vars.entry("SSL_CERT_FILE".into()).or_insert_with(|| bundle.clone());
            env_vars.entry("REQUESTS_CA_BUNDLE".into()).or_insert_with(|| bundle.clone());
            env_vars.entry("NODE_EXTRA_CA_CERTS".into()).or_insert(bundle);
        }
        let init = InitRequest {
            access_token: req.envd_access_token.clone(),
            env_vars,
            default_user: Some(req.default_user.clone().unwrap_or_else(|| rootfs::SANDBOX_USER.to_owned())),
            default_workdir: req.default_workdir.clone().or_else(|| Some(format!("/home/{}", rootfs::SANDBOX_USER))),
            timestamp: self.runtime.sets_guest_clock().then(now_rfc3339),
            ca_bundle: req.ca_bundle.clone(),
        };
        self.envd.init(addr, &init).await.map_err(internal)
    }

    /// Microvm templates ran their start command before the snapshot. The
    /// namespace runtime cannot snapshot processes, so it runs it per sandbox.
    async fn run_template_commands(&self, sb: &Sandbox, req: &StartSandboxRequest, template: &LocalTemplate) -> Result<()> {
        if !matches!(self.runtime, Runtime::Namespace(_)) {
            return Ok(());
        }
        let meta = self.templates.lock().expect("poisoned").get(&template.build_id).cloned();
        let Some(meta) = meta else { return Ok(()) };
        let addr = SocketAddr::new(sb.slot.ns_ip.into(), ENVD_PORT);
        let token = Some(req.envd_access_token.as_str());
        if let Some(start) = &meta.start_cmd {
            let bg = format!("nohup sh -c {} >/tmp/weft-start.log 2>&1 &", shell_quote(start));
            self.envd.run(addr, token, "root", &bg, Duration::from_secs(30)).await.map_err(internal)?;
        }
        if let Some(ready) = &meta.ready_cmd {
            let deadline = tokio::time::Instant::now() + READY_CMD_TIMEOUT;
            loop {
                if self.envd.run(addr, token, "root", ready, Duration::from_secs(30)).await.map_err(internal)? == 0 {
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(ManagerError::Internal("template ready command did not succeed in time".into()));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        Ok(())
    }

    async fn resume_existing(&self, sb: &Arc<Sandbox>, req: &StartSandboxRequest) -> Result<SandboxInfo> {
        let guard = sb.op.lock().await;
        match (sb.state(), &req.resume) {
            (SandboxState::Running, _) => Ok(sb.info()),
            (SandboxState::Paused, Some(ResumeSource::Local)) => {
                let handle = guard.as_ref().ok_or_else(|| internal("paused sandbox has no handle"))?;
                self.runtime.thaw(handle).await.map_err(internal)?;
                sb.set_state(SandboxState::Running);
                Ok(sb.info())
            }
            (state, _) => Err(ManagerError::Conflict(format!("sandbox is {state:?}"))),
        }
    }

    /// Stops every sandbox. Called on shutdown: a restarted agent cannot
    /// re-adopt running guests, so it must not leave them behind.
    pub async fn shutdown(&self) {
        let ids: Vec<String> = self.sandboxes.lock().expect("poisoned").keys().cloned().collect();
        for id in ids {
            self.remove(&id).await;
        }
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        validate_id("sandbox", id)?;
        self.remove(id).await;
        Ok(())
    }

    async fn remove(&self, id: &str) {
        let Some(sb) = self.sandboxes.lock().expect("poisoned").remove(id) else { return };
        sb.set_state(SandboxState::Stopping);
        let mut guard = sb.op.lock().await;
        if let Some(handle) = guard.take() {
            if let Err(e) = self.runtime.stop(handle).await {
                tracing::warn!(sandbox = %id, error = %e, "stopping guest failed");
            }
        }
        self.release_slot(&sb).await;
        let _ = tokio::fs::remove_dir_all(self.cfg.data_dir.join("sandboxes").join(id)).await;
    }

    async fn release_slot(&self, sb: &Sandbox) {
        self.slots.release(sb.slot.index);
        if let Err(e) = run_all(&self.runner, &net::teardown_plan(&sb.slot, &sb.link)).await {
            tracing::warn!(sandbox = %sb.id, error = %e, "network teardown failed");
        }
    }

    pub async fn pause(&self, id: &str, req: PauseRequest) -> Result<PauseResult> {
        let sb = self.get(id)?;
        let mut guard = sb.op.lock().await;
        match sb.state() {
            SandboxState::Running => {}
            SandboxState::Paused => return Err(ManagerError::Conflict("sandbox is already paused".into())),
            other => return Err(ManagerError::Conflict(format!("sandbox is {other:?}"))),
        }
        let handle = guard.take().ok_or_else(|| internal("running sandbox has no handle"))?;
        sb.set_state(SandboxState::Pausing);
        let work_dir = self.cfg.data_dir.join("sandboxes").join(id).join("pause");
        tokio::fs::create_dir_all(&work_dir).await.map_err(internal)?;
        match self.runtime.pause(handle, &work_dir).await {
            Ok(Paused::Frozen(h)) => {
                *guard = Some(h);
                sb.set_state(SandboxState::Paused);
                Ok(PauseResult::Local)
            }
            Ok(Paused::Snapshot(files)) => {
                drop(guard);
                let result = match &req.upload {
                    Some(targets) => self.upload_snapshot(&files, targets).await,
                    None => Err(ManagerError::BadRequest("this runtime needs upload targets to pause".into())),
                };
                self.remove(id).await;
                result
            }
            Err(e) => {
                drop(guard);
                self.remove(id).await;
                Err(internal(e))
            }
        }
    }

    async fn upload_snapshot(&self, files: &SnapshotFiles, t: &UploadTargets) -> Result<PauseResult> {
        let rootfs = self.transfer.upload(&files.rootfs, &t.rootfs).await.map_err(internal)?;
        let memory = self.transfer.upload(&files.memory, &t.memory).await.map_err(internal)?;
        let vmstate = self.transfer.upload(&files.vmstate, &t.vmstate).await.map_err(internal)?;
        Ok(PauseResult::Uploaded { rootfs, memory, vmstate })
    }

    async fn download_snapshot(&self, id: &str, s: &SnapshotArtifacts) -> Result<SnapshotFiles> {
        let dir = self.cfg.data_dir.join("sandboxes").join(id).join("resume");
        tokio::fs::create_dir_all(&dir).await.map_err(internal)?;
        let files = SnapshotFiles { rootfs: dir.join("rootfs.ext4"), memory: dir.join("memory"), vmstate: dir.join("vmstate") };
        self.transfer.download(&s.rootfs, &files.rootfs).await.map_err(internal)?;
        self.transfer.download(&s.memory, &files.memory).await.map_err(internal)?;
        self.transfer.download(&s.vmstate, &files.vmstate).await.map_err(internal)?;
        Ok(files)
    }

    pub fn update_egress(&self, id: &str, policy: &EgressPolicy) -> Result<()> {
        let sb = self.get(id)?;
        let compiled = CompiledPolicy::compile(policy).map_err(|e| ManagerError::BadRequest(e.to_string()))?;
        self.slots.set_policy(sb.slot.index, Arc::new(compiled));
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Arc<Sandbox>> {
        validate_id("sandbox", id)?;
        self.sandboxes
            .lock()
            .expect("poisoned")
            .get(id)
            .cloned()
            .ok_or_else(|| ManagerError::NotFound(format!("sandbox {id} is not on this host")))
    }

    pub fn list(&self) -> Vec<SandboxInfo> {
        let mut v: Vec<SandboxInfo> = self.sandboxes.lock().expect("poisoned").values().map(|s| s.info()).collect();
        v.sort_by(|a, b| a.sandbox_id.cmp(&b.sandbox_id));
        v
    }

    /// Where the tunnel should connect for a running sandbox's port.
    pub fn tunnel_target(&self, id: &str, port: u16) -> Result<SocketAddr> {
        let sb = self.get(id)?;
        match sb.state() {
            SandboxState::Running => Ok(SocketAddr::new(sb.slot.ns_ip.into(), port)),
            other => Err(ManagerError::Conflict(format!("sandbox is {other:?}"))),
        }
    }

    pub fn cached_templates(&self) -> Vec<String> {
        let mut v: Vec<String> = self.templates.lock().expect("poisoned").keys().cloned().collect();
        v.sort();
        v
    }

    // ---- templates ---------------------------------------------------------

    async fn ensure_template(&self, build_id: &str, artifacts: Option<&TemplateArtifacts>) -> Result<LocalTemplate> {
        let dir = self.cfg.data_dir.join("templates").join(build_id);
        if self.templates.lock().expect("poisoned").contains_key(build_id) {
            return Ok(LocalTemplate { build_id: build_id.to_owned(), dir });
        }
        let Some(artifacts) = artifacts else {
            return Err(ManagerError::Conflict(format!("template build {build_id} is not on this host")));
        };
        let lock = self.template_locks.lock().expect("poisoned").entry(build_id.to_owned()).or_default().clone();
        let _held = lock.lock().await;
        if self.templates.lock().expect("poisoned").contains_key(build_id) {
            return Ok(LocalTemplate { build_id: build_id.to_owned(), dir });
        }
        let partial = self.cfg.data_dir.join("templates").join(format!("{build_id}.partial"));
        let _ = tokio::fs::remove_dir_all(&partial).await;
        tokio::fs::create_dir_all(&partial).await.map_err(internal)?;
        self.transfer.download(&artifacts.rootfs, &partial.join("rootfs.ext4")).await.map_err(internal)?;
        self.transfer.download(&artifacts.memory, &partial.join("memory")).await.map_err(internal)?;
        self.transfer.download(&artifacts.vmstate, &partial.join("vmstate")).await.map_err(internal)?;
        let meta = TemplateMeta { build_id: build_id.to_owned(), start_cmd: None, ready_cmd: None };
        self.commit_template(&partial, &dir, meta).await?;
        Ok(LocalTemplate { build_id: build_id.to_owned(), dir })
    }

    async fn commit_template(&self, partial: &Path, dir: &Path, meta: TemplateMeta) -> Result<()> {
        let json = serde_json::to_vec_pretty(&meta).map_err(internal)?;
        tokio::fs::write(partial.join("template.json"), json).await.map_err(internal)?;
        let _ = tokio::fs::remove_dir_all(dir).await;
        tokio::fs::rename(partial, dir).await.map_err(internal)?;
        self.templates.lock().expect("poisoned").insert(meta.build_id.clone(), meta);
        Ok(())
    }

    pub fn build_status(&self, build_id: &str) -> Result<BuildStatus> {
        validate_id("build", build_id)?;
        self.builds
            .lock()
            .expect("poisoned")
            .get(build_id)
            .map(|s| s.lock().expect("poisoned").clone())
            .ok_or_else(|| ManagerError::NotFound(format!("no build {build_id} on this host")))
    }

    /// Starts a template build in the background.
    pub fn start_build(self: &Arc<Self>, build_id: &str, req: BuildTemplateRequest) -> Result<()> {
        validate_id("build", build_id)?;
        if req.vcpus == 0 || req.vcpus > self.cfg.max_vcpus || req.memory_mib < 128 || req.memory_mib > self.cfg.max_memory_mib {
            return Err(ManagerError::BadRequest("vcpus or memoryMib out of range".into()));
        }
        if req.disk_mib < 512 {
            return Err(ManagerError::BadRequest("diskMib must be at least 512".into()));
        }
        let status = Arc::new(Mutex::new(BuildStatus {
            build_id: build_id.to_owned(),
            status: BuildState::Building,
            error: None,
            logs: Vec::new(),
            envd_version: None,
            env_vars: BTreeMap::new(),
            default_workdir: None,
            artifacts: None,
        }));
        {
            let mut builds = self.builds.lock().expect("poisoned");
            if let Some(existing) = builds.get(build_id) {
                if existing.lock().expect("poisoned").status != BuildState::Failed {
                    return Err(ManagerError::Conflict(format!("build {build_id} already exists")));
                }
            }
            builds.insert(build_id.to_owned(), status.clone());
        }
        let this = self.clone();
        let build_id = build_id.to_owned();
        tokio::spawn(async move {
            let log = {
                let status = status.clone();
                move |line: String| {
                    let mut s = status.lock().expect("poisoned");
                    if s.logs.len() < MAX_BUILD_LOG_LINES {
                        s.logs.push(line);
                    }
                }
            };
            let result = this.run_build(&build_id, &req, &log).await;
            let _ = tokio::fs::remove_dir_all(this.cfg.data_dir.join("builds").join(&build_id)).await;
            let mut s = status.lock().expect("poisoned");
            match result {
                Ok((env, workdir, artifacts)) => {
                    s.status = BuildState::Ready;
                    s.env_vars = env;
                    s.default_workdir = workdir;
                    s.artifacts = artifacts;
                    s.envd_version = Some(crate::ENVD_VERSION.to_owned());
                    s.logs.push("template ready".into());
                }
                Err(e) => {
                    tracing::warn!(build = %build_id, error = %e, "template build failed");
                    s.status = BuildState::Failed;
                    s.error = Some(e.to_string());
                }
            }
        });
        Ok(())
    }

    async fn run_build(
        &self,
        build_id: &str,
        req: &BuildTemplateRequest,
        log: &(dyn Fn(String) + Send + Sync),
    ) -> Result<(BTreeMap<String, String>, Option<String>, Option<BuiltArtifacts>)> {
        let work = self.cfg.data_dir.join("builds").join(build_id);
        let layers_dir = work.join("layers");
        let rootfs_dir = work.join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.map_err(internal)?;

        let image = ImageRef::parse(&req.image.reference).map_err(|e| ManagerError::BadRequest(e.to_string()))?;
        log(format!("pulling {}/{}:{}", image.registry, image.repository, image.reference));
        let creds = Credentials { username: req.image.username.clone(), password: req.image.password.clone() };
        let mut puller = Puller::new(creds).map_err(internal)?;
        let pulled = puller.pull(&image, &layers_dir).await.map_err(|e| ManagerError::BadRequest(format!("pulling image: {e}")))?;
        log(format!("unpacking {} layers", pulled.layers.len()));
        let agent = std::env::current_exe().map_err(internal)?;
        for layer in &pulled.layers {
            let out = tokio::process::Command::new(&agent)
                .arg("unpack-layer")
                .arg(&rootfs_dir)
                .arg(&layer.path)
                .arg(&layer.media_type)
                .output()
                .await
                .map_err(internal)?;
            if !out.status.success() {
                return Err(ManagerError::BadRequest(format!(
                    "unpacking layer failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            let _ = tokio::fs::remove_file(&layer.path).await;
        }
        rootfs::prepare(&rootfs_dir, &self.cfg.guest_dir).map_err(|e| ManagerError::BadRequest(e.to_string()))?;

        let mut env = rootfs::parse_env(pulled.config.env.as_deref().unwrap_or_default());
        env.extend(req.env_vars.clone());
        let workdir = pulled.config.working_dir.filter(|w| !w.is_empty() && w != "/");

        let partial = self.cfg.data_dir.join("templates").join(format!("{build_id}.partial"));
        let _ = tokio::fs::remove_dir_all(&partial).await;
        let slot = self.slots.reserve().ok_or_else(|| ManagerError::Capacity("host is full".into()))?;
        let link = self.runtime.guest_link(&slot);
        let finished = async {
            run_all(&self.runner, &net::teardown_plan(&slot, &link)).await.map_err(internal)?;
            run_all(&self.runner, &net::setup_plan(self.slots.net(), &slot, &link)).await.map_err(internal)?;
            self.slots.occupy(slot.index, SlotEntry { sandbox_id: format!("build-{build_id}"), policy: Arc::new(CompiledPolicy::deny_all()) });
            log(format!("finishing template with the {} runtime", self.runtime.name()));
            self.runtime.finish_template(req, build_id, &rootfs_dir, &partial, &slot, log).await.map_err(internal)
        }
        .await;
        self.slots.release(slot.index);
        let _ = run_all(&self.runner, &net::teardown_plan(&slot, &link)).await;
        finished?;

        let artifacts = match &req.upload {
            Some(t) => {
                log("uploading template artifacts".into());
                Some(BuiltArtifacts {
                    rootfs: self.transfer.upload(&partial.join("rootfs.ext4"), &t.rootfs).await.map_err(internal)?,
                    memory: self.transfer.upload(&partial.join("memory"), &t.memory).await.map_err(internal)?,
                    vmstate: self.transfer.upload(&partial.join("vmstate"), &t.vmstate).await.map_err(internal)?,
                })
            }
            None => None,
        };
        let meta = TemplateMeta { build_id: build_id.to_owned(), start_cmd: req.start_cmd.clone(), ready_cmd: req.ready_cmd.clone() };
        let dir = self.cfg.data_dir.join("templates").join(build_id);
        self.commit_template(&partial, &dir, meta).await?;
        Ok((env, workdir, artifacts))
    }

    pub fn health(&self, capacity: Capacity, version: &str) -> HostHealth {
        let list = self.list();
        HostHealth {
            host_id: self.cfg.host_id.clone(),
            version: version.to_owned(),
            runtime: self.runtime.name().to_owned(),
            capacity,
            running: list.iter().filter(|s| s.state == SandboxState::Running).count() as u32,
            paused: list.iter().filter(|s| s.state == SandboxState::Paused).count() as u32,
        }
    }
}

/// Single-quotes a string for `sh -c`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ids() {
        assert!(validate_id("sandbox", "i7x2k9q3m1").is_ok());
        assert!(validate_id("build", "b-123").is_ok());
        for bad in ["", "UPPER", "a/b", "-lead", "a b", &"x".repeat(65), "../x", "a.b"] {
            assert!(validate_id("sandbox", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quotes_shell_arguments() {
        assert_eq!(shell_quote("echo 'hi'"), r"'echo '\''hi'\'''");
    }
}
