/**
 * Records the control plane keeps, and the storage interface.
 *
 * Production uses DynamoDB (one table per record type, encrypted with the
 * stack's KMS key); development and tests use the in-memory store. Both pass
 * the same contract tests.
 */
import type { EgressPolicy } from "../egress.js";

export interface Team {
  teamId: string;
  name: string;
  createdAt: string;
  /** Default egress policy for the team's sandboxes. Empty denies everything. */
  egressPolicy: EgressPolicy;
}

export interface ApiKey {
  /** SHA-256 of the key. The plaintext is shown once and never stored. */
  keyHash: string;
  keyId: string;
  teamId: string;
  role: "team" | "admin";
  name: string;
  /** First characters of the key, for recognizing it in listings. */
  prefix: string;
  createdAt: string;
}

export type BuildStatus = "building" | "ready" | "error";

export interface ArtifactObject {
  key: string;
  sha256: string;
  size: number;
}

export interface Template {
  templateId: string;
  /** Owning team; null for templates every team can use. */
  teamId: string | null;
  names: string[];
  image: string;
  /** Current ready build, used for new sandboxes. */
  buildId: string | null;
  /** The build in progress or last attempted. */
  latestBuildId: string;
  status: BuildStatus;
  error?: string;
  cpuCount: number;
  memoryMB: number;
  diskSizeMB: number;
  envVars: Record<string, string>;
  defaultWorkdir?: string;
  startCmd?: string;
  readyCmd?: string;
  envdVersion?: string;
  /** Firecracker artifacts in S3, per build. Absent for development hosts. */
  artifacts?: { rootfs: ArtifactObject; memory: ArtifactObject; vmstate: ArtifactObject };
  /** Host the build ran on (development hosts can only use their own builds). */
  builtOnHost?: string;
  createdAt: string;
  updatedAt: string;
}

export interface BuildRecord {
  buildId: string;
  templateId: string;
  status: BuildStatus;
  hostId: string;
  logs: string[];
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export type SandboxState = "starting" | "running" | "pausing" | "paused" | "resuming";

export interface SnapshotRef {
  kind: "local" | "s3";
  /** Host holding a local (frozen) snapshot. */
  hostId?: string;
  rootfs?: ArtifactObject;
  memory?: ArtifactObject;
  vmstate?: ArtifactObject;
}

export interface Sandbox {
  sandboxId: string;
  teamId: string;
  templateId: string;
  alias?: string;
  buildId: string;
  hostId: string | null;
  clientId: string;
  state: SandboxState;
  /** Monotonic version for optimistic concurrency. */
  version: number;
  envdAccessToken: string;
  trafficAccessToken: string | null;
  envdVersion: string;
  cpuCount: number;
  memoryMB: number;
  diskSizeMB: number;
  metadata: Record<string, string>;
  envVars: Record<string, string>;
  startedAt: string;
  endAt: string;
  autoPause: boolean;
  autoResume: boolean;
  allowInternetAccess: boolean | null;
  /** The E2B network config as the client sent it (echoed by get_info). */
  network?: Record<string, unknown>;
  egressPolicy: EgressPolicy;
  snapshot?: SnapshotRef;
  pausedAt?: string;
}

export interface Host {
  hostId: string;
  privateIp: string;
  apiPort: number;
  tunnelPort: number;
  certPem: string;
  token: string;
  version: string;
  runtime: string;
  capacity: { maxSandboxes: number; vcpus: number; memoryMib: number };
  sandboxes: { sandboxId: string; state: string }[];
  templates: string[];
  draining: boolean;
  lastHeartbeatAt: string;
  registeredAt: string;
}

export class VersionConflict extends Error {
  constructor(id: string) {
    super(`sandbox ${id} was modified concurrently`);
    this.name = "VersionConflict";
  }
}

export interface Store {
  putTeam(t: Team): Promise<void>;
  getTeam(teamId: string): Promise<Team | undefined>;
  listTeams(): Promise<Team[]>;

  putApiKey(k: ApiKey): Promise<void>;
  getApiKeyByHash(keyHash: string): Promise<ApiKey | undefined>;
  listApiKeys(teamId: string): Promise<ApiKey[]>;
  deleteApiKey(keyHash: string): Promise<void>;

  putTemplate(t: Template): Promise<void>;
  getTemplate(templateId: string): Promise<Template | undefined>;
  /** Templates owned by the team plus public ones. */
  listTemplatesVisibleTo(teamId: string): Promise<Template[]>;
  listAllTemplates(): Promise<Template[]>;
  deleteTemplate(templateId: string): Promise<void>;

  putBuild(b: BuildRecord): Promise<void>;
  getBuild(buildId: string): Promise<BuildRecord | undefined>;

  /** Creates a sandbox; fails if the ID exists. */
  createSandbox(s: Sandbox): Promise<void>;
  /**
   * Writes `s` if the stored version equals `s.version - 1`; throws
   * {@link VersionConflict} otherwise.
   */
  updateSandbox(s: Sandbox): Promise<void>;
  getSandbox(sandboxId: string): Promise<Sandbox | undefined>;
  deleteSandbox(sandboxId: string): Promise<void>;
  listSandboxesByTeam(teamId: string): Promise<Sandbox[]>;
  listAllSandboxes(): Promise<Sandbox[]>;

  putHost(h: Host): Promise<void>;
  getHost(hostId: string): Promise<Host | undefined>;
  listHosts(): Promise<Host[]>;
  deleteHost(hostId: string): Promise<void>;

  getMeta<T>(key: string): Promise<T | undefined>;
  putMeta<T>(key: string, value: T): Promise<void>;
}
