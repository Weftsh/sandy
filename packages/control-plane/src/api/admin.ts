/**
 * Weft administration API (`/weft/v1`): teams, API keys, egress policies,
 * image templates, license and fleet status. Admin keys can do everything;
 * team keys can manage their own templates and read their license status.
 */
import type { FastifyInstance, FastifyRequest } from "fastify";

import { ADMIN_TEAM_ID, type ApiKeys, type Principal } from "../auth/apikeys.js";
import { badRequest, notFound } from "../errors.js";
import { newTeamId } from "../ids.js";
import { DENY_ALL, validatePolicy } from "../egress.js";
import type { LicenseService } from "../license/service.js";
import type { HostRegistry } from "../hosts/registry.js";
import type { SandboxService } from "../sandboxes/service.js";
import type { ImageBuildOptions, TemplateService } from "../templates/service.js";
import type { Store, Team, Template } from "../store/types.js";

export interface AdminDeps {
  keys: ApiKeys;
  store: Store;
  templates: TemplateService;
  sandboxes: SandboxService;
  license: LicenseService;
  hosts: HostRegistry;
}

type Req = FastifyRequest<{ Params: Record<string, string>; Querystring: Record<string, string>; Body: unknown }>;

const obj = (b: unknown): Record<string, unknown> => {
  if (b === undefined || b === null) return {};
  if (typeof b !== "object" || Array.isArray(b)) throw badRequest("request body must be a JSON object");
  return b as Record<string, unknown>;
};

function teamView(t: Team) {
  return { teamId: t.teamId, name: t.name, createdAt: t.createdAt, egressPolicy: t.egressPolicy };
}

function templateView(t: Template, logs?: string[], error?: string) {
  return {
    templateId: t.templateId,
    names: t.names,
    public: t.teamId === null,
    teamId: t.teamId,
    image: t.image,
    status: t.status,
    buildId: t.buildId,
    latestBuildId: t.latestBuildId,
    cpuCount: t.cpuCount,
    memoryMB: t.memoryMB,
    diskSizeMB: t.diskSizeMB,
    envdVersion: t.envdVersion,
    error: error ?? t.error,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
    ...(logs ? { logs } : {}),
  };
}

function buildOptions(b: Record<string, unknown>): ImageBuildOptions {
  const str = (k: string) => (typeof b[k] === "string" ? (b[k] as string) : undefined);
  const num = (k: string) => (typeof b[k] === "number" ? (b[k] as number) : undefined);
  const env = b.envVars ?? {};
  if (typeof env !== "object" || env === null || Array.isArray(env)) throw badRequest("envVars must be an object");
  const registry = b.registry as { username?: unknown; password?: unknown } | undefined;
  return {
    name: str("name") ?? "",
    image: str("image") ?? "",
    cpuCount: num("cpuCount"),
    memoryMB: num("memoryMB"),
    diskSizeMB: num("diskSizeMB"),
    envVars: env as Record<string, string>,
    defaultWorkdir: str("defaultWorkdir"),
    startCmd: str("startCmd"),
    readyCmd: str("readyCmd"),
    public: b.public === true,
    registry:
      registry && typeof registry.username === "string" && typeof registry.password === "string"
        ? { username: registry.username, password: registry.password }
        : undefined,
  };
}

export function registerAdminRoutes(app: FastifyInstance, d: AdminDeps): void {
  const admin = (req: Req): Promise<Principal> => d.keys.requireAdmin(req.headers);
  const any = (req: Req): Promise<Principal> => d.keys.authenticate(req.headers);

  // ---- license ---------------------------------------------------------------
  app.get("/weft/v1/license", async (req: Req) => {
    await admin(req);
    return d.license.status();
  });
  app.put("/weft/v1/license", async (req: Req) => {
    await admin(req);
    const key = obj(req.body).key;
    if (typeof key !== "string" || !key) throw badRequest("key is required");
    return d.license.installKey(key);
  });

  // ---- teams and keys ----------------------------------------------------------
  app.get("/weft/v1/teams", async (req: Req) => {
    await admin(req);
    return (await d.store.listTeams()).map(teamView);
  });
  app.post("/weft/v1/teams", async (req: Req, reply) => {
    await admin(req);
    const name = obj(req.body).name;
    if (typeof name !== "string" || !name.trim() || name.length > 100) throw badRequest("name is required (up to 100 characters)");
    const team: Team = { teamId: newTeamId(), name: name.trim(), createdAt: new Date().toISOString(), egressPolicy: DENY_ALL };
    await d.store.putTeam(team);
    const { key, record } = await d.keys.create(team.teamId, "team", "initial key");
    reply.code(201);
    return { team: teamView(team), apiKey: { keyId: record.keyId, key, note: "Store this key now; it cannot be shown again." } };
  });
  app.get("/weft/v1/teams/:teamId", async (req: Req) => {
    await admin(req);
    const t = await d.store.getTeam(req.params.teamId!);
    if (!t) throw notFound("team not found");
    return teamView(t);
  });
  app.put("/weft/v1/teams/:teamId/egress", async (req: Req) => {
    await admin(req);
    const t = await d.store.getTeam(req.params.teamId!);
    if (!t) throw notFound("team not found");
    t.egressPolicy = validatePolicy(req.body);
    await d.store.putTeam(t);
    await d.sandboxes.applyTeamPolicy(t.teamId);
    return teamView(t);
  });
  app.get("/weft/v1/teams/:teamId/api-keys", async (req: Req) => {
    await admin(req);
    return (await d.store.listApiKeys(req.params.teamId!)).map(({ keyHash: _h, ...rest }) => rest);
  });
  app.post("/weft/v1/teams/:teamId/api-keys", async (req: Req, reply) => {
    await admin(req);
    const teamId = req.params.teamId!;
    const isAdminTeam = teamId === ADMIN_TEAM_ID;
    if (!isAdminTeam && !(await d.store.getTeam(teamId))) throw notFound("team not found");
    const name = obj(req.body).name;
    const { key, record } = await d.keys.create(teamId, isAdminTeam ? "admin" : "team", typeof name === "string" ? name.slice(0, 100) : "api key");
    reply.code(201);
    return { keyId: record.keyId, key, note: "Store this key now; it cannot be shown again." };
  });
  app.delete("/weft/v1/teams/:teamId/api-keys/:keyId", async (req: Req, reply) => {
    await admin(req);
    if (!(await d.keys.revoke(req.params.teamId!, req.params.keyId!))) throw notFound("key not found");
    reply.code(204);
  });

  // ---- templates -----------------------------------------------------------------
  app.get("/weft/v1/templates", async (req: Req) => {
    const p = await any(req);
    const list = p.role === "admin" ? await d.store.listAllTemplates() : await d.templates.list(p.teamId);
    return list.map((t) => templateView(t));
  });
  app.post("/weft/v1/templates", async (req: Req, reply) => {
    const p = await any(req);
    const { template } = await d.templates.buildFromImage(p, buildOptions(obj(req.body)));
    reply.code(202);
    return templateView(template);
  });
  app.post("/weft/v1/templates/:id/rebuild", async (req: Req, reply) => {
    const p = await any(req);
    const existing = await d.templates.get(p, req.params.id!);
    const opts = buildOptions({ name: existing.names[0], image: existing.image, public: existing.teamId === null, ...obj(req.body) });
    const { template } = await d.templates.buildFromImage(p, opts, existing.templateId);
    reply.code(202);
    return templateView(template);
  });
  app.get("/weft/v1/templates/:id", async (req: Req) => {
    const p = await any(req);
    const t = await d.templates.get(p, req.params.id!);
    const build = await d.store.getBuild(t.latestBuildId);
    return templateView(t, build?.logs, build?.status === "error" ? build.error : undefined);
  });
  app.delete("/weft/v1/templates/:id", async (req: Req, reply) => {
    await d.templates.delete(await any(req), req.params.id!);
    reply.code(204);
  });

  // ---- fleet -----------------------------------------------------------------------
  app.get("/weft/v1/hosts", async (req: Req) => {
    await admin(req);
    return (await d.store.listHosts()).map((h) => ({
      hostId: h.hostId,
      privateIp: h.privateIp,
      runtime: h.runtime,
      version: h.version,
      live: d.hosts.isLive(h),
      draining: h.draining,
      capacity: h.capacity,
      sandboxes: h.sandboxes.length,
      templates: h.templates.length,
      lastHeartbeatAt: h.lastHeartbeatAt,
    }));
  });
  app.get("/weft/v1/sandboxes", async (req: Req) => {
    await admin(req);
    return (await d.store.listAllSandboxes()).map((s) => ({ ...d.sandboxes.listed(s), teamId: s.teamId, hostId: s.hostId, internalState: s.state }));
  });
}
