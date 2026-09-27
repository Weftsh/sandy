/**
 * Templates: OCI images turned into sandbox templates by a host.
 *
 * A template is built from an image reference (ECR or any registry). The
 * host pulls it, installs envd and the init, and (on Firecracker) boots it
 * once and snapshots it, so the first sandbox restores from the snapshot.
 * Firecracker artifacts go to S3 so every host can use them.
 */
import { badRequest, conflict, forbidden, notFound, unavailable } from "../errors.js";
import { NAME_RE, newBuildId, newTemplateId } from "../ids.js";
import type { ArtifactStore, PendingUpload, UploadedArtifact } from "../artifacts.js";
import type { HostRegistry } from "../hosts/registry.js";
import { HostError } from "../hosts/client.js";
import type { Principal } from "../auth/apikeys.js";
import type { BuildRecord, Store, Template } from "../store/types.js";
import type { Logger } from "../log.js";

export interface ImageBuildOptions {
  name: string;
  image: string;
  cpuCount?: number;
  memoryMB?: number;
  diskSizeMB?: number;
  envVars?: Record<string, string>;
  defaultWorkdir?: string;
  startCmd?: string;
  readyCmd?: string;
  /** Admin only: make the template usable by every team. */
  public?: boolean;
  /** The team that owns the template. Admins must set this or `public`;
   * team keys may only name their own team. */
  teamId?: string;
  /** Credentials for a private registry other than the stack's ECR. */
  registry?: { username: string; password: string };
}

interface HostBuildStatus {
  buildId: string;
  status: "building" | "ready" | "failed";
  error?: string | null;
  logs: string[];
  envdVersion?: string | null;
  envVars?: Record<string, string>;
  defaultWorkdir?: string | null;
  artifacts?: { rootfs: UploadedArtifact; memory: UploadedArtifact; vmstate: UploadedArtifact } | null;
}

export interface RegistryCredentials {
  /** Returns short-lived pull credentials for images in the stack's ECR registry. */
  forImage(image: string): Promise<{ username: string; password: string } | undefined>;
}

export interface TemplateDefaults {
  vcpus: number;
  memoryMib: number;
  diskMib: number;
}

const MAX_LOGS = 2000;

export class TemplateService {
  private polling = new Set<string>();
  private uploads = new Map<string, PendingUpload>();

  constructor(
    private store: Store,
    private hosts: HostRegistry,
    private artifacts: ArtifactStore | undefined,
    private registries: RegistryCredentials | undefined,
    private defaults: TemplateDefaults,
    private log: Logger,
  ) {}

  /**
   * Resolves what the SDK sends as `templateID`: an ID, a name, `name:tag`
   * or `namespace/name[:tag]`. Only the default tag is supported. Templates
   * the team owns win over public ones with the same name.
   */
  async resolve(teamId: string, ref: string): Promise<Template | undefined> {
    const withoutNamespace = ref.includes("/") ? ref.slice(ref.lastIndexOf("/") + 1) : ref;
    const colon = withoutNamespace.indexOf(":");
    const name = (colon >= 0 ? withoutNamespace.slice(0, colon) : withoutNamespace).toLowerCase();
    const tag = colon >= 0 ? withoutNamespace.slice(colon + 1) : undefined;
    if (tag !== undefined && tag !== "default" && tag !== "latest") return undefined;
    const visible = await this.store.listTemplatesVisibleTo(teamId);
    const matches = visible.filter((t) => t.templateId === name || t.names.includes(name));
    return matches.find((t) => t.teamId === teamId) ?? matches[0];
  }

  async list(teamId: string): Promise<Template[]> {
    return (await this.store.listTemplatesVisibleTo(teamId)).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async get(principal: Principal, templateId: string): Promise<Template> {
    const t = await this.store.getTemplate(templateId);
    if (!t || (t.teamId !== null && t.teamId !== principal.teamId && principal.role !== "admin")) throw notFound(`template ${templateId} not found`);
    return t;
  }

  async delete(principal: Principal, templateId: string): Promise<void> {
    const t = await this.store.getTemplate(templateId);
    if (!t) throw notFound(`template ${templateId} not found`);
    const owns = t.teamId === principal.teamId || principal.role === "admin";
    if (!owns) throw t.teamId === null ? forbidden("only admins can delete public templates") : notFound(`template ${templateId} not found`);
    await this.store.deleteTemplate(templateId);
    if (this.artifacts && t.artifacts) {
      await this.artifacts.delete([t.artifacts.rootfs, t.artifacts.memory, t.artifacts.vmstate]).catch(() => {});
    }
  }

  /** Creates or rebuilds a template from an image. */
  async buildFromImage(principal: Principal, opts: ImageBuildOptions, existingId?: string): Promise<{ template: Template; build: BuildRecord }> {
    const name = opts.name.toLowerCase();
    if (!NAME_RE.test(name)) throw badRequest("template name must be 1-63 lowercase letters, digits, - or _, starting with a letter or digit");
    if (!opts.image || opts.image.length > 512) throw badRequest("image is required");
    if (opts.public && principal.role !== "admin") throw forbidden("only admins can create public templates");
    if (opts.public && opts.teamId) throw badRequest("a template is either public or owned by one team, not both");
    let teamId: string | null;
    if (opts.public) {
      teamId = null;
    } else if (opts.teamId && opts.teamId !== principal.teamId) {
      if (principal.role !== "admin") throw forbidden("team keys can only build templates for their own team");
      if (!(await this.store.getTeam(opts.teamId))) throw notFound(`team ${opts.teamId} not found`);
      teamId = opts.teamId;
    } else if (principal.role === "admin") {
      // The admin pseudo-team runs no sandboxes; a template there would be
      // invisible to every real team.
      throw badRequest("choose who can use the template: a team (teamId, CLI --team <team-id>) or every team (public, CLI --public)");
    } else {
      teamId = principal.teamId;
    }
    const existing = existingId
      ? await this.store.getTemplate(existingId)
      : (await this.store.listTemplatesVisibleTo(teamId ?? principal.teamId)).find((t) => t.teamId === teamId && t.names.includes(name));
    if (existing && existing.status === "building") throw conflict(`template ${name} is already building`);
    const template = this.nextTemplate(existing, { ...opts, teamId, name });
    return this.dispatch(template, template.latestBuildId, opts);
  }

  /**
   * First half of the SDK's `Template.build`: records the template and a
   * build that waits for its definition.
   */
  async reserveBuild(principal: Principal, opts: { name: string; cpuCount?: number; memoryMB?: number }): Promise<{ templateId: string; buildId: string }> {
    const name = opts.name.toLowerCase();
    if (!NAME_RE.test(name)) throw badRequest("template name must be 1-63 lowercase letters, digits, - or _, starting with a letter or digit");
    const existing = (await this.store.listTemplatesVisibleTo(principal.teamId)).find((t) => t.teamId === principal.teamId && t.names.includes(name));
    if (existing && existing.status === "building" && existing.latestBuildId) {
      const b = await this.store.getBuild(existing.latestBuildId);
      if (b && b.hostId) throw conflict(`template ${name} is already building`);
    }
    const template = this.nextTemplate(existing, { teamId: principal.teamId, name, image: existing?.image ?? "", cpuCount: opts.cpuCount, memoryMB: opts.memoryMB });
    const now = template.updatedAt;
    await this.store.putBuild({ buildId: template.latestBuildId, templateId: template.templateId, status: "building", hostId: "", logs: [], createdAt: now, updatedAt: now });
    await this.store.putTemplate(template);
    return { templateId: template.templateId, buildId: template.latestBuildId };
  }

  /** Second half of `Template.build`: starts the reserved build from an image. */
  async startReservedBuild(
    principal: Principal,
    templateId: string,
    buildId: string,
    opts: Omit<ImageBuildOptions, "name" | "public">,
  ): Promise<void> {
    const template = await this.store.getTemplate(templateId);
    const build = await this.store.getBuild(buildId);
    if (!template || !build || build.templateId !== templateId || (template.teamId !== principal.teamId && principal.role !== "admin")) {
      throw notFound(`build ${buildId} not found`);
    }
    if (template.latestBuildId !== buildId || build.status !== "building" || build.hostId) throw conflict(`build ${buildId} was already started`);
    const next: Template = {
      ...template,
      image: opts.image,
      envVars: opts.envVars ?? {},
      defaultWorkdir: opts.defaultWorkdir,
      startCmd: opts.startCmd,
      readyCmd: opts.readyCmd,
    };
    validateResources(next);
    try {
      await this.dispatch(next, buildId, opts);
    } catch (e) {
      await this.finish(build, "error", e instanceof Error ? e.message : String(e));
      throw e;
    }
  }

  private nextTemplate(
    existing: Template | undefined,
    opts: { teamId: string | null; name: string } & Partial<Omit<ImageBuildOptions, "teamId">>,
  ): Template {
    const now = new Date().toISOString();
    const template: Template = {
      templateId: existing?.templateId ?? newTemplateId(),
      teamId: opts.teamId,
      names: existing?.names ?? [opts.name],
      image: opts.image ?? existing?.image ?? "",
      buildId: existing?.buildId ?? null,
      latestBuildId: newBuildId(),
      status: "building",
      cpuCount: opts.cpuCount ?? existing?.cpuCount ?? this.defaults.vcpus,
      memoryMB: opts.memoryMB ?? existing?.memoryMB ?? this.defaults.memoryMib,
      diskSizeMB: opts.diskSizeMB ?? existing?.diskSizeMB ?? this.defaults.diskMib,
      envVars: opts.envVars ?? {},
      defaultWorkdir: opts.defaultWorkdir,
      startCmd: opts.startCmd,
      readyCmd: opts.readyCmd,
      envdVersion: existing?.envdVersion,
      artifacts: existing?.artifacts,
      builtOnHost: existing?.builtOnHost,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    validateResources(template);
    return template;
  }

  /** Sends a build to a host and starts following it. */
  private async dispatch(
    template: Template,
    buildId: string,
    opts: { image: string; registry?: { username: string; password: string } },
  ): Promise<{ template: Template; build: BuildRecord }> {
    const host = await this.hosts.pick({ buildId });
    if (!host) throw unavailable("no sandbox host is available to build the template");
    let upload: PendingUpload | undefined;
    if (host.runtime === "firecracker") {
      if (!this.artifacts) throw unavailable("an artifacts bucket is required to build templates on Firecracker hosts");
      upload = await this.artifacts.beginUpload(`templates/${template.templateId}/${buildId}`);
    }
    const auth = opts.registry ?? (await this.registries?.forImage(opts.image));
    const request = {
      templateId: template.templateId,
      image: { reference: opts.image, username: auth?.username, password: auth?.password },
      vcpus: template.cpuCount,
      memoryMib: template.memoryMB,
      diskMib: template.diskSizeMB,
      startCmd: template.startCmd,
      readyCmd: template.readyCmd,
      envVars: template.envVars,
      upload: upload?.targets,
    };
    try {
      await this.hosts.client(host).request("POST", `/v1/templates/${buildId}`, request);
    } catch (e) {
      await upload?.abort();
      throw e instanceof HostError ? badRequest(`build could not start: ${e.message}`) : e;
    }
    if (upload) this.uploads.set(buildId, upload);
    const now = new Date().toISOString();
    const build: BuildRecord = { buildId, templateId: template.templateId, status: "building", hostId: host.hostId, logs: [], createdAt: now, updatedAt: now };
    template.latestBuildId = buildId;
    template.status = "building";
    template.updatedAt = now;
    await this.store.putBuild(build);
    await this.store.putTemplate(template);
    this.log.info("template build started", { templateId: template.templateId, buildId, hostId: host.hostId, image: opts.image });
    void this.follow(buildId);
    return { template, build };
  }

  /** Polls a build until it finishes. Safe to call more than once. */
  async follow(buildId: string): Promise<void> {
    if (this.polling.has(buildId)) return;
    this.polling.add(buildId);
    try {
      for (let i = 0; i < 3600; i++) {
        const done = await this.syncBuild(buildId).catch((e: unknown) => {
          this.log.warn("build status poll failed", { buildId, error: String(e) });
          return false;
        });
        if (done) return;
        await new Promise((r) => setTimeout(r, 1000));
      }
    } finally {
      this.polling.delete(buildId);
    }
  }

  /** One poll of a build's host. Returns true once the build is final. */
  async syncBuild(buildId: string): Promise<boolean> {
    const build = await this.store.getBuild(buildId);
    if (!build || build.status !== "building") return true;
    const client = await this.hosts.clientFor(build.hostId);
    if (!client) {
      if (Date.now() - Date.parse(build.updatedAt) > 120_000) await this.finish(build, "error", "the build host went away");
      return false;
    }
    const status = await client.request<HostBuildStatus>("GET", `/v1/templates/${buildId}`);
    build.logs = status.logs.slice(0, MAX_LOGS);
    build.updatedAt = new Date().toISOString();
    if (status.status === "building") {
      await this.store.putBuild(build);
      return false;
    }
    if (status.status === "failed") {
      await this.uploads.get(buildId)?.abort();
      this.uploads.delete(buildId);
      await this.finish(build, "error", status.error ?? "build failed");
      return true;
    }
    const template = await this.store.getTemplate(build.templateId);
    if (!template) return true;
    let artifacts = template.artifacts;
    if (status.artifacts) {
      const upload = this.uploads.get(buildId);
      if (!upload) {
        await this.finish(build, "error", "the control plane restarted during the build; build again");
        return true;
      }
      artifacts = await upload.complete(status.artifacts);
      this.uploads.delete(buildId);
    }
    const old = template.artifacts && template.buildId !== buildId ? template.artifacts : undefined;
    template.buildId = buildId;
    template.status = "ready";
    template.error = undefined;
    template.envdVersion = status.envdVersion ?? undefined;
    template.envVars = status.envVars ?? template.envVars;
    template.defaultWorkdir = template.defaultWorkdir ?? status.defaultWorkdir ?? undefined;
    template.artifacts = status.artifacts ? artifacts : undefined;
    template.builtOnHost = build.hostId;
    template.updatedAt = new Date().toISOString();
    await this.store.putTemplate(template);
    build.status = "ready";
    await this.store.putBuild(build);
    if (old && this.artifacts) await this.artifacts.delete([old.rootfs, old.memory, old.vmstate]).catch(() => {});
    this.log.info("template ready", { templateId: template.templateId, buildId });
    return true;
  }

  /**
   * Marks a reserved build that never started as failed with `reason`, so
   * the template shows why (for example an unsupported build step) instead
   * of being swept later as abandoned. No-op for builds that started.
   */
  async failReservedBuild(principal: Principal, templateId: string, buildId: string, reason: string): Promise<void> {
    const template = await this.store.getTemplate(templateId);
    const build = await this.store.getBuild(buildId);
    if (!template || !build || build.templateId !== templateId) return;
    if (template.teamId !== principal.teamId && principal.role !== "admin") return;
    if (template.latestBuildId !== buildId || build.status !== "building" || build.hostId) return;
    await this.finish(build, "error", reason);
  }

  private async finish(build: BuildRecord, status: "error", error: string): Promise<void> {
    build.status = status;
    build.error = error;
    build.updatedAt = new Date().toISOString();
    await this.store.putBuild(build);
    const template = await this.store.getTemplate(build.templateId);
    if (template && template.latestBuildId === build.buildId) {
      template.status = template.buildId ? "ready" : "error";
      template.error = error;
      template.updatedAt = build.updatedAt;
      await this.store.putTemplate(template);
    }
    this.log.warn("template build failed", { templateId: build.templateId, buildId: build.buildId, error });
  }

  /** Builds configured public templates that do not exist yet. */
  async ensureBootstrapTemplates(templates: { name: string; image: string }[], admin: Principal): Promise<void> {
    for (const t of templates) {
      const existing = (await this.store.listAllTemplates()).find((x) => x.teamId === null && x.names.includes(t.name));
      if (existing && (existing.status !== "error" || existing.buildId)) continue;
      // Retry failed bootstrap builds every few minutes, not on every tick.
      if (existing && Date.now() - Date.parse(existing.updatedAt) < 180_000) continue;
      if (!(await this.hosts.pick({ buildId: "" }))) return;
      await this.buildFromImage(admin, { name: t.name, image: t.image, public: true }, existing?.templateId).catch((e: unknown) =>
        this.log.warn("bootstrap template build failed to start", { name: t.name, error: String(e) }),
      );
    }
  }

  /** Resumes following builds that were in progress when this process started. */
  async resumeFollowing(): Promise<void> {
    for (const t of await this.store.listAllTemplates()) {
      if (t.status === "building") void this.follow(t.latestBuildId);
    }
  }
}

function validateResources(t: Template): void {
  if (!Number.isInteger(t.cpuCount) || t.cpuCount < 1 || t.cpuCount > 64) throw badRequest("cpuCount must be 1-64");
  if (!Number.isInteger(t.memoryMB) || t.memoryMB < 128 || t.memoryMB > 262_144) throw badRequest("memoryMB must be 128-262144");
  if (!Number.isInteger(t.diskSizeMB) || t.diskSizeMB < 512 || t.diskSizeMB > 1_048_576) throw badRequest("diskSizeMB must be 512-1048576");
  for (const [k, v] of Object.entries(t.envVars)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || typeof v !== "string") throw badRequest(`invalid environment variable ${k}`);
  }
}
