/**
 * Sandbox lifecycle, as the E2B SDKs expect it.
 *
 * `create` and `connect` return only after the host reports the sandbox
 * running, which it does only after envd holds the sandbox's access token:
 * the SDKs send commands immediately and never poll for readiness.
 *
 * Every state change is a versioned write, so a timeout, a pause and a kill
 * racing each other resolve to one outcome.
 */
import http from "node:http";
import { randomBytes } from "node:crypto";

import { ApiError, badRequest, conflict, internal, notFound, unavailable } from "../errors.js";
import { newSandboxId, newToken, SANDBOX_ID_RE } from "../ids.js";
import { DENY_ALL, sandboxPolicy, type EgressPolicy } from "../egress.js";
import type { Artifacts, PendingUpload, UploadedArtifact } from "../artifacts.js";
import { HostError, type HostClient } from "../hosts/client.js";
import type { HostRegistry } from "../hosts/registry.js";
import type { TemplateService } from "../templates/service.js";
import type { Principal } from "../auth/apikeys.js";
import { VersionConflict, type Host, type Sandbox, type Store, type Template } from "../store/types.js";
import type { Logger } from "../log.js";

export const ENVD_PORT = 49983;
const PAUSE_TIMEOUT_MS = 20 * 60_000;
const START_TIMEOUT_MS = 10 * 60_000;
const MAX_PLACEMENT_ATTEMPTS = 3;

export interface SandboxServiceOptions {
  domain: string;
  defaultTimeoutSec: number;
  maxTimeoutSec: number;
  pausedRetentionDays: number;
  egressCaCert?: string;
}

export interface UsageRecorder {
  recordConcurrency(running: number): Promise<void>;
}

/** Create/connect response (`Sandbox` in E2B's OpenAPI). */
export interface SandboxResponse {
  templateID: string;
  alias?: string;
  sandboxID: string;
  clientID: string;
  envdVersion: string;
  envdAccessToken: string;
  trafficAccessToken: string | null;
  domain: string;
}

export interface ListedSandbox {
  templateID: string;
  alias?: string;
  sandboxID: string;
  clientID: string;
  startedAt: string;
  endAt: string;
  cpuCount: number;
  memoryMB: number;
  diskSizeMB: number;
  state: "running" | "paused";
  envdVersion: string;
  metadata: Record<string, string>;
}

/**
 * Size limits keep a sandbox record well inside DynamoDB's 400 KB item limit,
 * so oversized input is a 400 here instead of a storage error later.
 */
export const MAP_LIMITS = { metadata: 32 * 1024, envVars: 128 * 1024 } as const;

const stringMap = (raw: unknown, field: keyof typeof MAP_LIMITS): Record<string, string> => {
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== "object" || Array.isArray(raw)) throw badRequest(`${field} must be an object of strings`);
  const out: Record<string, string> = {};
  let bytes = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v !== "string") throw badRequest(`${field}.${k} must be a string`);
    if (!k || /[=\0]/.test(k) || (field === "envVars" && /\s/.test(k))) throw badRequest(`${field} has an invalid name ${JSON.stringify(k)}`);
    bytes += Buffer.byteLength(k) + Buffer.byteLength(v);
    if (bytes > MAP_LIMITS[field]) throw badRequest(`${field} is larger than ${MAP_LIMITS[field] / 1024} KiB`);
    out[k] = v;
  }
  return out;
};

export class SandboxService {
  constructor(
    private store: Store,
    private hosts: HostRegistry,
    private templates: TemplateService,
    private artifacts: Artifacts | undefined,
    private usage: UsageRecorder,
    private opts: SandboxServiceOptions,
    private log: Logger,
  ) {}

  private timeout(raw: unknown): number {
    if (raw === undefined || raw === null) return this.opts.defaultTimeoutSec;
    if (typeof raw !== "number" || !Number.isFinite(raw) || raw < 0) throw badRequest("timeout must be a non-negative number of seconds");
    return Math.min(Math.max(1, Math.ceil(raw)), this.opts.maxTimeoutSec);
  }

  private async owned(principal: Principal, sandboxId: string): Promise<Sandbox> {
    if (!SANDBOX_ID_RE.test(sandboxId)) throw notFound(`sandbox ${sandboxId} not found`);
    const s = await this.store.getSandbox(sandboxId);
    if (!s || (s.teamId !== principal.teamId && principal.role !== "admin")) throw notFound(`sandbox ${sandboxId} not found`);
    return s;
  }

  /** Writes the next version of a sandbox. */
  private async save(s: Sandbox): Promise<Sandbox> {
    const next = { ...s, version: s.version + 1 };
    await this.store.updateSandbox(next);
    return next;
  }

  response(s: Sandbox): SandboxResponse {
    return {
      templateID: s.templateId,
      ...(s.alias ? { alias: s.alias } : {}),
      sandboxID: s.sandboxId,
      clientID: s.clientId,
      envdVersion: s.envdVersion,
      envdAccessToken: s.envdAccessToken,
      trafficAccessToken: s.trafficAccessToken,
      domain: this.opts.domain,
    };
  }

  listed(s: Sandbox): ListedSandbox {
    return {
      templateID: s.templateId,
      ...(s.alias ? { alias: s.alias } : {}),
      sandboxID: s.sandboxId,
      clientID: s.clientId,
      startedAt: s.startedAt,
      endAt: s.endAt,
      cpuCount: s.cpuCount,
      memoryMB: s.memoryMB,
      diskSizeMB: s.diskSizeMB,
      state: s.state === "paused" || s.state === "resuming" ? "paused" : "running",
      envdVersion: s.envdVersion,
      metadata: s.metadata,
    };
  }

  detail(s: Sandbox): Record<string, unknown> {
    return {
      ...this.listed(s),
      envdAccessToken: s.envdAccessToken,
      allowInternetAccess: s.allowInternetAccess,
      domain: this.opts.domain,
      // Python's SDK parses these as objects; they must be omitted, not null.
      ...(s.network ? { network: s.network } : {}),
      lifecycle: { autoResume: s.autoResume, onTimeout: s.autoPause ? "pause" : "kill" },
    };
  }

  // ---- create -------------------------------------------------------------

  async create(principal: Principal, body: Record<string, unknown>): Promise<SandboxResponse> {
    const ref = body.templateID ?? "base";
    if (typeof ref !== "string" || !ref || ref.length > 256) throw badRequest("templateID must be a string");
    for (const unsupported of ["mcp", "iam"] as const) {
      if (body[unsupported] !== undefined && body[unsupported] !== null) throw badRequest(`${unsupported} is not supported by this deployment`);
    }
    if (Array.isArray(body.volumeMounts) && body.volumeMounts.length > 0) throw badRequest("volumeMounts are not supported by this deployment");
    const autoResume = body.autoResume as { enabled?: unknown } | null | undefined;
    if (typeof autoResume === "object" && autoResume !== null && autoResume.enabled === true) {
      // Traffic to a paused sandbox does not wake it; failing here beats a
      // sandbox that silently stays paused.
      throw badRequest("autoResume is not supported by this deployment yet; resume paused sandboxes with Sandbox.connect()");
    }
    const metadata = stringMap(body.metadata, "metadata");
    const envVars = stringMap(body.envVars, "envVars");
    const timeoutSec = this.timeout(body.timeout);
    const allowInternetAccess = typeof body.allow_internet_access === "boolean" ? body.allow_internet_access : null;
    const network = body.network && typeof body.network === "object" ? (body.network as Record<string, unknown>) : undefined;

    const template = await this.templates.resolve(principal.teamId, ref);
    if (!template) throw notFound(`template '${ref}' not found`);
    if (!template.buildId) {
      throw badRequest(template.status === "building" ? `template '${ref}' is still building` : `template '${ref}' has no successful build`);
    }
    const team = await this.store.getTeam(principal.teamId);
    const policy = sandboxPolicy(team?.egressPolicy ?? DENY_ALL, { allowInternetAccess, network });

    const now = new Date();
    const sandbox: Sandbox = {
      sandboxId: newSandboxId(),
      teamId: principal.teamId,
      templateId: template.templateId,
      alias: template.names[0],
      buildId: template.buildId,
      hostId: null,
      clientId: randomBytes(4).toString("hex"),
      state: "starting",
      version: 1,
      envdAccessToken: newToken(),
      trafficAccessToken: network?.allowPublicTraffic === false ? newToken() : null,
      envdVersion: template.envdVersion ?? "0.9.0",
      cpuCount: template.cpuCount,
      memoryMB: template.memoryMB,
      diskSizeMB: template.diskSizeMB,
      metadata,
      envVars,
      startedAt: now.toISOString(),
      endAt: new Date(now.getTime() + timeoutSec * 1000).toISOString(),
      autoPause: body.autoPause === true,
      autoResume: false,
      allowInternetAccess,
      network,
      egressPolicy: policy,
    };
    await this.store.createSandbox(sandbox);
    try {
      const started = await this.place(sandbox, template, undefined);
      const done = await this.save({
        ...sandbox,
        state: "running",
        hostId: started.host.hostId,
        envdVersion: started.envdVersion ?? sandbox.envdVersion,
        startedAt: new Date().toISOString(),
        endAt: new Date(Date.now() + timeoutSec * 1000).toISOString(),
      });
      void this.recordUsage(principal.teamId);
      this.log.info("sandbox created", { sandboxId: done.sandboxId, teamId: done.teamId, templateId: done.templateId, hostId: done.hostId });
      return this.response(done);
    } catch (e) {
      await this.store.deleteSandbox(sandbox.sandboxId);
      throw e;
    }
  }

  /** Starts (or resumes) a sandbox on a host, trying other hosts on capacity errors. */
  private async place(
    s: Sandbox,
    template: Template,
    resume: { kind: "local"; hostId: string } | { kind: "remote" } | undefined,
  ): Promise<{ host: Host; envdVersion?: string }> {
    const exclude = new Set<string>();
    let lastError: unknown;
    for (let attempt = 0; attempt < MAX_PLACEMENT_ATTEMPTS; attempt++) {
      const requiredHost = resume?.kind === "local" ? resume.hostId : template.artifacts ? undefined : template.builtOnHost;
      const host = await this.hosts.pick({ buildId: s.buildId, requiredHost, exclude });
      if (!host) break;
      const release = this.hosts.reserve(host.hostId);
      try {
        const request = await this.startRequest(s, template, host, resume);
        const info = await this.hosts
          .client(host)
          .request<{ envdVersion?: string | null }>("PUT", `/v1/sandboxes/${s.sandboxId}`, request, START_TIMEOUT_MS);
        return { host, envdVersion: info.envdVersion ?? undefined };
      } catch (e) {
        lastError = e;
        exclude.add(host.hostId);
        const retryable = e instanceof HostError && (e.status >= 500 || e.status === 409);
        this.log.warn("sandbox placement failed", { sandboxId: s.sandboxId, hostId: host.hostId, error: String(e), retryable });
        if (!retryable) break;
        // The host may have started it before failing; make sure it is gone.
        await this.hosts.client(host).request("DELETE", `/v1/sandboxes/${s.sandboxId}`).catch(() => {});
      } finally {
        release();
      }
    }
    if (lastError instanceof HostError && lastError.status === 400) throw badRequest(lastError.message);
    if (lastError instanceof HostError && lastError.status === 503) {
      throw unavailable("every sandbox host is at capacity; try again shortly");
    }
    if (lastError) throw internal(`sandbox could not be started: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
    throw unavailable("no sandbox host has capacity right now; try again shortly");
  }

  private async startRequest(
    s: Sandbox,
    template: Template,
    host: Host,
    resume: { kind: "local"; hostId: string } | { kind: "remote" } | undefined,
  ): Promise<Record<string, unknown>> {
    let templateArtifacts: unknown;
    if (host.runtime === "firecracker" && template.artifacts && !host.templates.includes(s.buildId)) {
      if (!this.artifacts) throw unavailable("the artifacts bucket is not configured");
      templateArtifacts = await this.artifacts.presign(template.artifacts);
    }
    let resumeSource: unknown;
    if (resume?.kind === "local") resumeSource = { kind: "local" };
    if (resume?.kind === "remote") {
      const snap = s.snapshot;
      if (!this.artifacts || !snap?.rootfs || !snap.memory || !snap.vmstate) throw internal("snapshot is incomplete");
      resumeSource = { kind: "remote", snapshot: await this.artifacts.presign({ rootfs: snap.rootfs, memory: snap.memory, vmstate: snap.vmstate }) };
    }
    return {
      teamId: s.teamId,
      templateId: s.templateId,
      buildId: s.buildId,
      templateArtifacts,
      vcpus: s.cpuCount,
      memoryMib: s.memoryMB,
      envVars: { ...template.envVars, ...s.envVars },
      envdAccessToken: s.envdAccessToken,
      defaultUser: "user",
      defaultWorkdir: template.defaultWorkdir,
      egress: s.egressPolicy,
      caBundle: s.egressPolicy.credentials.length > 0 ? this.opts.egressCaCert : undefined,
      resume: resumeSource,
    };
  }

  private async recordUsage(teamId: string): Promise<void> {
    try {
      const all = await this.store.listAllSandboxes();
      await this.usage.recordConcurrency(all.filter((s) => s.state !== "paused").length);
    } catch (e) {
      this.log.warn("recording usage failed", { teamId, error: String(e) });
    }
  }

  // ---- connect / resume ---------------------------------------------------

  async connect(principal: Principal, sandboxId: string, body: Record<string, unknown>): Promise<{ status: 200 | 201; body: SandboxResponse }> {
    const timeoutSec = this.timeout(body.timeout);
    for (let attempt = 0; attempt < 60; attempt++) {
      const s = await this.owned(principal, sandboxId);
      try {
        if (s.state === "running") {
          const endAt = Math.max(Date.parse(s.endAt), Date.now() + timeoutSec * 1000);
          const saved = await this.save({ ...s, endAt: new Date(endAt).toISOString() });
          return { status: 200, body: this.response(saved) };
        }
        if (s.state === "paused") return { status: 201, body: await this.resume(s, timeoutSec) };
      } catch (e) {
        if (!(e instanceof VersionConflict)) throw e;
      }
      // starting, pausing or resuming: wait for it to settle.
      await new Promise((r) => setTimeout(r, 500));
    }
    throw conflict("sandbox is busy; try again");
  }

  private async resume(s: Sandbox, timeoutSec: number): Promise<SandboxResponse> {
    const template = (await this.store.getTemplate(s.templateId)) ?? missingTemplate(s);
    const snap = s.snapshot;
    if (!snap) throw notFound(`Paused sandbox ${s.sandboxId} not found`);
    let resuming = await this.save({ ...s, state: "resuming" });
    try {
      const placed =
        snap.kind === "local"
          ? await this.place(resuming, template, { kind: "local", hostId: snap.hostId ?? "" })
          : await this.place(resuming, template, { kind: "remote" });
      resuming = await this.save({
        ...resuming,
        state: "running",
        hostId: placed.host.hostId,
        envdVersion: placed.envdVersion ?? resuming.envdVersion,
        endAt: new Date(Date.now() + timeoutSec * 1000).toISOString(),
        snapshot: undefined,
        pausedAt: undefined,
      });
      if (snap.kind === "s3" && this.artifacts) await this.artifacts.delete([snap.rootfs, snap.memory, snap.vmstate]).catch(() => {});
      void this.recordUsage(s.teamId);
      return this.response(resuming);
    } catch (e) {
      const current = await this.store.getSandbox(s.sandboxId);
      if (current && current.state === "resuming") {
        const hostGone = snap.kind === "local" && !(await this.hosts.clientFor(snap.hostId ?? ""));
        if (hostGone) {
          await this.store.deleteSandbox(s.sandboxId);
          throw notFound(`Paused sandbox ${s.sandboxId} not found: its host is gone`);
        }
        await this.save({ ...current, state: "paused" }).catch(() => {});
      }
      throw e;
    }
  }

  // ---- kill / pause / timeout --------------------------------------------

  async kill(principal: Principal, sandboxId: string): Promise<void> {
    const s = await this.owned(principal, sandboxId);
    await this.destroy(s);
  }

  /** Removes a sandbox everywhere. Idempotent. */
  async destroy(s: Sandbox): Promise<void> {
    await this.store.deleteSandbox(s.sandboxId);
    const hostId = s.hostId ?? s.snapshot?.hostId;
    if (hostId) {
      const client = await this.hosts.clientFor(hostId);
      await client?.request("DELETE", `/v1/sandboxes/${s.sandboxId}`).catch((e: unknown) =>
        this.log.warn("host did not confirm sandbox stop", { sandboxId: s.sandboxId, hostId, error: String(e) }),
      );
    }
    if (s.snapshot?.kind === "s3" && this.artifacts) {
      await this.artifacts.delete([s.snapshot.rootfs, s.snapshot.memory, s.snapshot.vmstate]).catch(() => {});
    }
    this.log.info("sandbox removed", { sandboxId: s.sandboxId, teamId: s.teamId });
  }

  async setTimeout(principal: Principal, sandboxId: string, body: Record<string, unknown>): Promise<void> {
    if (body.timeout === undefined) throw badRequest("timeout is required");
    const timeoutSec = this.timeout(body.timeout);
    for (let attempt = 0; attempt < 5; attempt++) {
      const s = await this.owned(principal, sandboxId);
      try {
        await this.save({ ...s, endAt: new Date(Date.now() + timeoutSec * 1000).toISOString() });
        return;
      } catch (e) {
        if (!(e instanceof VersionConflict)) throw e;
      }
    }
    throw conflict("sandbox is busy; try again");
  }

  async pause(principal: Principal, sandboxId: string): Promise<void> {
    const s = await this.owned(principal, sandboxId);
    await this.pauseSandbox(s);
  }

  async pauseSandbox(s: Sandbox): Promise<void> {
    if (s.state === "paused") throw conflict(`sandbox ${s.sandboxId} is already paused`);
    if (s.state !== "running" || !s.hostId) throw conflict(`sandbox ${s.sandboxId} is busy`);
    const client = await this.hosts.clientFor(s.hostId);
    if (!client) throw unavailable("the sandbox's host is not reachable");
    let pausing = await this.save({ ...s, state: "pausing" });
    let upload: PendingUpload | undefined;
    try {
      if (client.host.runtime === "firecracker") {
        if (!this.artifacts) throw unavailable("an artifacts bucket is required to pause Firecracker sandboxes");
        upload = await this.artifacts.beginUpload(`snapshots/${s.sandboxId}/${Date.now()}`);
      }
      const result = await client.request<
        { kind: "local" } | { kind: "uploaded"; rootfs: UploadedArtifact; memory: UploadedArtifact; vmstate: UploadedArtifact }
      >("POST", `/v1/sandboxes/${s.sandboxId}/pause`, { upload: upload?.targets }, PAUSE_TIMEOUT_MS);
      const snapshot =
        result.kind === "local"
          ? { kind: "local" as const, hostId: s.hostId }
          : { kind: "s3" as const, ...(await upload!.complete({ rootfs: result.rootfs, memory: result.memory, vmstate: result.vmstate })) };
      pausing = await this.save({
        ...pausing,
        state: "paused",
        hostId: result.kind === "local" ? s.hostId : null,
        snapshot,
        pausedAt: new Date().toISOString(),
      });
      this.log.info("sandbox paused", { sandboxId: s.sandboxId, snapshot: snapshot.kind });
    } catch (e) {
      await upload?.abort();
      if (e instanceof HostError && e.status === 409) {
        await this.save({ ...pausing, state: "running" }).catch(() => {});
        throw conflict(e.message);
      }
      // The host drops a sandbox whose pause failed.
      this.log.error("pause failed; removing sandbox", { sandboxId: s.sandboxId, error: String(e) });
      await this.destroy(pausing);
      throw e instanceof ApiError ? e : internal(`pause failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // ---- read ----------------------------------------------------------------

  async get(principal: Principal, sandboxId: string): Promise<Record<string, unknown>> {
    return this.detail(await this.owned(principal, sandboxId));
  }

  async list(
    principal: Principal,
    q: { state?: string; metadata?: string; limit?: string; nextToken?: string; template?: string; order?: string; startedAfter?: string },
    v1 = false,
  ): Promise<{ items: ListedSandbox[]; nextToken?: string }> {
    const states = new Set((q.state ?? (v1 ? "running" : "running,paused")).split(",").map((x) => x.trim()));
    const filters = parseMetadataFilter(q.metadata);
    const startedAfter = q.startedAfter ? Date.parse(q.startedAfter) : undefined;
    let items = (await this.store.listSandboxesByTeam(principal.teamId))
      .map((s) => ({ s, listed: this.listed(s) }))
      .filter(({ listed }) => states.has(listed.state))
      .filter(({ s }) => Object.entries(filters).every(([k, v]) => s.metadata[k] === v))
      .filter(({ s }) => !q.template || s.templateId === q.template || s.alias === q.template)
      .filter(({ s }) => startedAfter === undefined || Number.isNaN(startedAfter) || Date.parse(s.startedAt) > startedAfter)
      .map(({ listed }) => listed);
    items.sort((a, b) => (q.order === "asc" ? 1 : -1) * a.startedAt.localeCompare(b.startedAt) || a.sandboxID.localeCompare(b.sandboxID));
    const offset = q.nextToken ? Number(Buffer.from(q.nextToken, "base64url").toString("utf8")) : 0;
    if (!Number.isInteger(offset) || offset < 0) throw badRequest("invalid nextToken");
    const limit = q.limit ? Math.min(Math.max(1, Number(q.limit) || 100), 1000) : v1 ? 10_000 : 100;
    const page = items.slice(offset, offset + limit);
    const more = offset + limit < items.length;
    items = page;
    return { items, nextToken: more ? Buffer.from(String(offset + limit)).toString("base64url") : undefined };
  }

  async metrics(principal: Principal, sandboxId: string): Promise<Record<string, unknown>[]> {
    const s = await this.owned(principal, sandboxId);
    if (s.state !== "running" || !s.hostId) return [];
    const client = await this.hosts.clientFor(s.hostId);
    if (!client) return [];
    const res = await httpOverTunnel(client, s.sandboxId, ENVD_PORT, "GET", "/metrics", { "x-access-token": s.envdAccessToken });
    if (res.status !== 200) return [];
    const m = JSON.parse(res.body) as Record<string, number>;
    const ts = typeof m.ts === "number" ? m.ts : Math.floor(Date.now() / 1000);
    return [
      {
        timestamp: new Date(ts * 1000).toISOString(),
        timestampUnix: ts,
        cpuCount: m.cpu_count ?? s.cpuCount,
        cpuUsedPct: m.cpu_used_pct ?? 0,
        memUsed: m.mem_used ?? 0,
        memTotal: m.mem_total ?? 0,
        memCache: m.mem_cache ?? 0,
        diskUsed: m.disk_used ?? 0,
        diskTotal: m.disk_total ?? 0,
      },
    ];
  }

  // ---- egress / network ----------------------------------------------------

  /** What the egress gateway needs to decide on a sandbox's connection. */
  async egressFor(sandboxId: string): Promise<{ sandboxId: string; hostIp: string; policy: EgressPolicy } | undefined> {
    if (!SANDBOX_ID_RE.test(sandboxId)) return undefined;
    const s = await this.store.getSandbox(sandboxId);
    if (!s || s.state !== "running" || !s.hostId) return undefined;
    const host = await this.store.getHost(s.hostId);
    if (!host || !this.hosts.isLive(host)) return undefined;
    return { sandboxId, hostIp: host.privateIp, policy: s.egressPolicy };
  }

  async updateNetwork(principal: Principal, sandboxId: string, body: Record<string, unknown>): Promise<void> {
    const s = await this.owned(principal, sandboxId);
    const team = await this.store.getTeam(s.teamId);
    const allowInternetAccess = typeof body.allow_internet_access === "boolean" ? body.allow_internet_access : null;
    const { allow_internet_access: _ignored, ...network } = body;
    const policy = sandboxPolicy(team?.egressPolicy ?? DENY_ALL, { allowInternetAccess, network });
    const saved = await this.save({ ...s, egressPolicy: policy, network, allowInternetAccess });
    if (saved.state === "running" && saved.hostId) {
      const client = await this.hosts.clientFor(saved.hostId);
      await client?.request("PUT", `/v1/sandboxes/${sandboxId}/egress`, policy);
    }
  }

  /**
   * Re-applies a team's egress policy to the team's existing sandboxes, so
   * removing access takes effect for them too, not only for new sandboxes.
   * A sandbox whose SDK network options no longer fit the new policy loses
   * all egress (fail closed).
   */
  async applyTeamPolicy(teamId: string): Promise<void> {
    const team = await this.store.getTeam(teamId);
    const teamPolicy = team?.egressPolicy ?? DENY_ALL;
    for (const listed of await this.store.listSandboxesByTeam(teamId)) {
      for (let attempt = 0; attempt < 3; attempt++) {
        const s = await this.store.getSandbox(listed.sandboxId);
        if (!s) break;
        let policy: EgressPolicy;
        try {
          policy = sandboxPolicy(teamPolicy, { allowInternetAccess: s.allowInternetAccess, network: s.network });
        } catch {
          policy = DENY_ALL;
        }
        let saved: Sandbox;
        try {
          saved = await this.save({ ...s, egressPolicy: policy });
        } catch (e) {
          if (e instanceof VersionConflict) continue;
          throw e;
        }
        if (saved.state === "running" && saved.hostId) {
          const client = await this.hosts.clientFor(saved.hostId);
          await client?.request("PUT", `/v1/sandboxes/${saved.sandboxId}/egress`, policy).catch((err: unknown) =>
            this.log.warn("pushing egress policy to host failed", { sandboxId: saved.sandboxId, hostId: saved.hostId, error: String(err) }),
          );
        }
        break;
      }
    }
  }

  /**
   * Asks hosts to delete cached template builds that no template or sandbox
   * references any more (deleted templates, superseded builds), so hosts'
   * data volumes do not fill up. Hosts are read before templates: a build a
   * host reports was dispatched earlier, so its template already names it.
   */
  async evictStaleBuilds(): Promise<void> {
    const hosts = await this.hosts.liveHosts();
    if (hosts.length === 0) return;
    const live = new Set<string>();
    for (const t of await this.store.listAllTemplates()) {
      if (t.buildId) live.add(t.buildId);
      if (t.latestBuildId) live.add(t.latestBuildId);
    }
    for (const s of await this.store.listAllSandboxes()) live.add(s.buildId);
    for (const host of hosts) {
      const client = this.hosts.client(host);
      for (const buildId of host.templates.filter((b) => !live.has(b))) {
        try {
          await client.request("DELETE", `/v1/templates/${encodeURIComponent(buildId)}`);
          this.log.info("evicted unused template build", { hostId: host.hostId, buildId });
        } catch (e) {
          // 409: a sandbox still runs from it; 404: already gone.
          if (!(e instanceof HostError && (e.status === 409 || e.status === 404))) {
            this.log.warn("evicting a template build failed", { hostId: host.hostId, buildId, error: String(e) });
          }
        }
      }
    }
  }

  // ---- background ----------------------------------------------------------

  /** Kills or pauses expired sandboxes and cleans up stale records. */
  async reap(now = Date.now()): Promise<void> {
    for (const s of await this.store.listAllSandboxes()) {
      try {
        if (s.state === "running" && Date.parse(s.endAt) <= now) {
          if (s.autoPause) await this.pauseSandbox(s);
          else await this.destroy(s);
          continue;
        }
        if (s.state === "paused" && s.pausedAt && now - Date.parse(s.pausedAt) > this.opts.pausedRetentionDays * 86_400_000) {
          await this.destroy(s);
          continue;
        }
        const stuck = (s.state === "starting" || s.state === "resuming" || s.state === "pausing") && now - Date.parse(s.startedAt) > 3 * START_TIMEOUT_MS;
        if (stuck && s.state === "starting") await this.destroy(s);
      } catch (e) {
        if (!(e instanceof VersionConflict)) this.log.warn("reaper action failed", { sandboxId: s.sandboxId, error: String(e) });
      }
    }
  }

  /**
   * Reconciles records with what a host reports: sandboxes the host no longer
   * runs are gone (host restart, crash), and sandboxes the host runs without
   * a record are orphans to stop.
   */
  /**
   * Drops records of sandboxes a host no longer runs and stops sandboxes it
   * runs without a record. Normally a sandbox gets a minute of grace (the
   * heartbeat may predate it); right after the host agent restarted
   * (`restarted`), sandboxes started before the restart are dropped at once.
   */
  async reconcileHost(host: Host, now = Date.now(), restarted = false): Promise<void> {
    const reported = new Map(host.sandboxes.map((x) => [x.sandboxId, x.state]));
    const records = (await this.store.listAllSandboxes()).filter((s) => s.hostId === host.hostId || s.snapshot?.hostId === host.hostId);
    const registeredAt = Date.parse(host.registeredAt);
    for (const s of records) {
      const settled = s.state === "running" || (s.state === "paused" && s.snapshot?.kind === "local");
      const graceOver = now - Date.parse(s.startedAt) > 60_000 && (!s.pausedAt || now - Date.parse(s.pausedAt) > 60_000);
      const predatesRestart = restarted && Date.parse(s.startedAt) < registeredAt && (!s.pausedAt || Date.parse(s.pausedAt) < registeredAt);
      if (settled && (graceOver || predatesRestart) && !reported.has(s.sandboxId)) {
        this.log.warn("sandbox lost by its host", { sandboxId: s.sandboxId, hostId: host.hostId });
        await this.store.deleteSandbox(s.sandboxId);
      }
    }
    const known = new Set(records.map((s) => s.sandboxId));
    const client = this.hosts.client(host);
    for (const id of reported.keys()) {
      if (known.has(id)) continue;
      const record = await this.store.getSandbox(id);
      // Still being placed: a start, or a resume from S3, whose record does
      // not name this host until the VM is up.
      if (record && (record.state === "starting" || record.state === "resuming")) continue;
      this.log.warn("stopping orphaned sandbox", { sandboxId: id, hostId: host.hostId });
      await client.request("DELETE", `/v1/sandboxes/${id}`).catch(() => {});
    }
  }

  /** Drops sandboxes on hosts that stopped sending heartbeats. */
  async sweepDeadHosts(now = Date.now()): Promise<void> {
    const hosts = await this.store.listHosts();
    const dead = new Set(hosts.filter((h) => now - Date.parse(h.lastHeartbeatAt) > 120_000).map((h) => h.hostId));
    if (dead.size === 0) return;
    for (const s of await this.store.listAllSandboxes()) {
      const onDead = (s.hostId && dead.has(s.hostId)) || (s.snapshot?.kind === "local" && s.snapshot.hostId && dead.has(s.snapshot.hostId));
      if (onDead) {
        this.log.warn("sandbox lost with its host", { sandboxId: s.sandboxId, hostId: s.hostId ?? s.snapshot?.hostId });
        await this.store.deleteSandbox(s.sandboxId);
      }
    }
    for (const h of hosts) {
      if (now - Date.parse(h.lastHeartbeatAt) > 86_400_000) await this.store.deleteHost(h.hostId);
    }
  }
}

function missingTemplate(s: Sandbox): never {
  throw notFound(`template ${s.templateId} of sandbox ${s.sandboxId} no longer exists`);
}

/**
 * Parses the SDKs' double-encoded metadata filter: a query string whose keys
 * and values are themselves percent-encoded.
 */
export function parseMetadataFilter(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of new URLSearchParams(raw)) {
    try {
      out[decodeURIComponent(k)] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

/** Makes one HTTP request to a sandbox port through the host tunnel. */
export async function httpOverTunnel(
  client: HostClient,
  sandboxId: string,
  port: number,
  method: string,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const socket = await client.openTunnel(sandboxId, port);
  return new Promise((resolve, reject) => {
    const req = http.request(
      { method, path, headers: { host: `${port}-${sandboxId}`, connection: "close", ...headers }, createConnection: () => socket as never, timeout: 10_000 },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 502, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("sandbox request timed out")));
    req.on("error", reject);
    req.end();
  });
}
