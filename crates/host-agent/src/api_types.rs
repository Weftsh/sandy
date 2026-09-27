//! JSON contract between the control plane and the host agent.
//!
//! The control plane's TypeScript client (`packages/control-plane/src/hosts`)
//! mirrors these types. Field names are camelCase on the wire.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use weft_netpolicy::EgressPolicy;

/// `PUT /v1/sandboxes/{sandboxId}`: start a sandbox, from its template or from
/// a pause snapshot. Idempotent: repeating it for a running sandbox returns
/// the current state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartSandboxRequest {
    pub team_id: String,
    pub template_id: String,
    pub build_id: String,
    /// Where to fetch the template when this host has not cached it.
    #[serde(default)]
    pub template_artifacts: Option<TemplateArtifacts>,
    pub vcpus: u32,
    pub memory_mib: u32,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    /// Token envd requires on every request (`X-Access-Token`).
    pub envd_access_token: String,
    #[serde(default)]
    pub default_user: Option<String>,
    #[serde(default)]
    pub default_workdir: Option<String>,
    #[serde(default)]
    pub egress: EgressPolicy,
    /// PEM certificate of the egress gateway's interception CA. Sent only when
    /// the egress policy carries credentials.
    #[serde(default)]
    pub ca_bundle: Option<String>,
    /// Resume from a pause snapshot instead of the template.
    #[serde(default)]
    pub resume: Option<ResumeSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ResumeSource {
    /// The snapshot is still on this host (the development runtime always
    /// resumes this way).
    Local,
    /// Download the snapshot written by a previous pause.
    #[serde(rename_all = "camelCase")]
    Remote { snapshot: SnapshotArtifacts },
}

/// A downloadable artifact with its integrity hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRef {
    /// Presigned HTTPS GET URL.
    pub url: String,
    /// Hex SHA-256 of the object as stored (compressed).
    pub sha256: String,
    pub size: u64,
}

/// Firecracker template artifacts: a zstd-compressed ext4 root filesystem and
/// the snapshot taken after the template's first boot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateArtifacts {
    pub rootfs: ArtifactRef,
    pub memory: ArtifactRef,
    pub vmstate: ArtifactRef,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotArtifacts {
    pub rootfs: ArtifactRef,
    pub memory: ArtifactRef,
    pub vmstate: ArtifactRef,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SandboxState {
    Starting,
    Running,
    Pausing,
    Paused,
    Stopping,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxInfo {
    pub sandbox_id: String,
    pub state: SandboxState,
    /// Reported by envd on `/init`.
    pub envd_version: Option<String>,
    /// RFC 3339.
    pub started_at: String,
}

/// Where the host uploads an artifact: one presigned PUT, or the parts of a
/// multipart upload the control plane started and will complete.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum UploadTarget {
    #[serde(rename_all = "camelCase")]
    Put { url: String },
    #[serde(rename_all = "camelCase")]
    Multipart { part_size: u64, part_urls: Vec<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UploadTargets {
    pub rootfs: UploadTarget,
    pub memory: UploadTarget,
    pub vmstate: UploadTarget,
}

/// `POST /v1/sandboxes/{sandboxId}/pause`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PauseRequest {
    /// Where to write the snapshot. Omitted for the development runtime,
    /// which keeps paused sandboxes frozen in place.
    #[serde(default)]
    pub upload: Option<UploadTargets>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UploadedArtifact {
    pub sha256: String,
    pub size: u64,
    /// ETags of a multipart upload, in part order. Empty for single PUTs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<UploadedPart>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UploadedPart {
    pub part_number: u32,
    pub etag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PauseResult {
    /// Frozen in place on this host.
    Local,
    /// Written to the upload targets; the sandbox's resources are released.
    #[serde(rename_all = "camelCase")]
    Uploaded {
        rootfs: UploadedArtifact,
        memory: UploadedArtifact,
        vmstate: UploadedArtifact,
    },
}

/// `PUT /v1/sandboxes/{sandboxId}/egress`: replace the egress policy used by
/// the guest resolver. The gateway fetches policies from the control plane.
pub type UpdateEgressRequest = EgressPolicy;

/// `POST /v1/templates/{buildId}`: build a template from an OCI image.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildTemplateRequest {
    pub template_id: String,
    pub image: ImageSource,
    pub vcpus: u32,
    pub memory_mib: u32,
    /// Size of the root filesystem the sandbox sees.
    pub disk_mib: u32,
    #[serde(default)]
    pub start_cmd: Option<String>,
    #[serde(default)]
    pub ready_cmd: Option<String>,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    /// Where to upload the built artifacts so other hosts can use them.
    /// Omitted for the development runtime.
    #[serde(default)]
    pub upload: Option<UploadTargets>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSource {
    /// `registry/repository[:tag][@digest]`, e.g. an ECR image URI.
    pub reference: String,
    /// Registry credentials, e.g. from ECR GetAuthorizationToken. Short-lived.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BuildState {
    Building,
    Ready,
    Failed,
}

/// `GET /v1/templates/{buildId}`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BuildStatus {
    pub build_id: String,
    pub status: BuildState,
    pub error: Option<String>,
    /// Build log lines, oldest first; capped.
    pub logs: Vec<String>,
    pub envd_version: Option<String>,
    pub artifacts: Option<BuiltArtifacts>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BuiltArtifacts {
    pub rootfs: UploadedArtifact,
    pub memory: UploadedArtifact,
    pub vmstate: UploadedArtifact,
}

/// `GET /v1/health`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostHealth {
    pub host_id: String,
    pub version: String,
    pub runtime: String,
    pub capacity: Capacity,
    pub running: u32,
    pub paused: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Capacity {
    pub max_sandboxes: u32,
    pub vcpus: u32,
    pub memory_mib: u64,
}

/// Body of the host's periodic `POST /internal/v1/hosts/heartbeat` to the
/// control plane. Registers the host and refreshes its liveness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    pub host_id: String,
    pub private_ip: String,
    pub api_port: u16,
    pub tunnel_port: u16,
    /// Self-signed certificate the control plane and edge proxy pin.
    pub cert_pem: String,
    /// Bearer token the control plane and edge proxy present to this host.
    pub token: String,
    pub version: String,
    pub runtime: String,
    pub capacity: Capacity,
    pub sandboxes: Vec<HeartbeatSandbox>,
    /// Template builds cached on this host.
    pub templates: Vec<String>,
    pub draining: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatSandbox {
    pub sandbox_id: String,
    pub state: SandboxState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    pub heartbeat_interval_sec: u64,
}

/// Error body for every non-2xx response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: u16,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_request_wire_format() {
        let json = r#"{
            "teamId":"t1","templateId":"base","buildId":"b1",
            "vcpus":2,"memoryMib":512,
            "envVars":{"A":"1"},"envdAccessToken":"tok",
            "defaultUser":"user",
            "egress":{"allow":[{"host":"pypi.org"}]},
            "resume":{"kind":"local"}
        }"#;
        let req: StartSandboxRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.resume, Some(ResumeSource::Local));
        assert_eq!(req.egress.allow.len(), 1);
        assert!(serde_json::from_str::<StartSandboxRequest>(r#"{"teamId":"t","bogus":1}"#).is_err());
    }

    #[test]
    fn upload_target_wire_format() {
        let t: UploadTarget = serde_json::from_str(
            r#"{"kind":"multipart","partSize":268435456,"partUrls":["https://a","https://b"]}"#,
        )
        .unwrap();
        assert_eq!(
            t,
            UploadTarget::Multipart { part_size: 268_435_456, part_urls: vec!["https://a".into(), "https://b".into()] }
        );
        let r = serde_json::to_value(PauseResult::Local).unwrap();
        assert_eq!(r, serde_json::json!({"kind":"local"}));
    }
}
