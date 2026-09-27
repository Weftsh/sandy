/**
 * E2B-compatible REST API, as used by the unmodified E2B SDKs (2.x).
 *
 * Status codes follow the Python SDK's strict expectations: 201 for create,
 * 202 for template requests, 201 for the file-upload link, 204 for actions.
 */
import type { FastifyInstance, FastifyRequest } from "fastify";

import { badRequest, notFound, forbidden, ApiError } from "../errors.js";
import type { ApiKeys, Principal } from "../auth/apikeys.js";
import type { SandboxService } from "../sandboxes/service.js";
import type { TemplateService } from "../templates/service.js";
import type { Store, Template } from "../store/types.js";

export interface E2BDeps {
  keys: ApiKeys;
  sandboxes: SandboxService;
  templates: TemplateService;
  store: Store;
}

type Req = FastifyRequest<{ Params: Record<string, string>; Querystring: Record<string, string>; Body: unknown }>;

const body = (req: Req): Record<string, unknown> => {
  const b = req.body;
  if (b === undefined || b === null) return {};
  if (typeof b !== "object" || Array.isArray(b)) throw badRequest("request body must be a JSON object");
  return b as Record<string, unknown>;
};

function templateSummary(t: Template): Record<string, unknown> {
  return {
    templateID: t.templateId,
    buildID: t.buildId ?? t.latestBuildId,
    cpuCount: t.cpuCount,
    memoryMB: t.memoryMB,
    diskSizeMB: t.diskSizeMB,
    public: t.teamId === null,
    aliases: t.names,
    names: t.names,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
    createdBy: null,
    lastSpawnedAt: null,
    spawnCount: 0,
    buildCount: 1,
    envdVersion: t.envdVersion ?? "",
    buildStatus: t.status,
  };
}

/** Steps of the SDK's `Template.build` that map onto an image build. */
function interpretSteps(steps: unknown): { envVars: Record<string, string>; workdir?: string } {
  const envVars: Record<string, string> = {};
  let workdir: string | undefined;
  if (steps === undefined || steps === null) return { envVars };
  if (!Array.isArray(steps)) throw badRequest("steps must be a list");
  for (const raw of steps) {
    const step = raw as { type?: string; args?: string[] };
    const args = Array.isArray(step.args) ? step.args : [];
    switch (step.type) {
      case "ENV":
        for (let i = 0; i + 1 < args.length; i += 2) envVars[String(args[i])] = String(args[i + 1]);
        break;
      case "WORKDIR":
        workdir = args[0];
        break;
      case "USER":
        // Sandboxes always run commands as `user` by default.
        break;
      case "RUN":
      case "COPY":
        throw badRequest(
          `${step.type} steps are not supported yet. Build a container image (for example with a Dockerfile), push it to your stack's ECR repository and use fromImage.`,
        );
      default:
        throw badRequest(`unsupported template step ${String(step.type)}`);
    }
  }
  return { envVars, workdir };
}

export function registerE2BRoutes(app: FastifyInstance, d: E2BDeps): void {
  const auth = (req: Req): Promise<Principal> => d.keys.authenticate(req.headers);

  // ---- sandboxes -----------------------------------------------------------
  const create = async (req: Req, reply: import("fastify").FastifyReply) => {
    const p = await auth(req);
    reply.code(201);
    return d.sandboxes.create(p, body(req));
  };
  app.post("/sandboxes", create);
  app.post("/v2/sandboxes", create);

  app.get("/sandboxes", async (req: Req) => {
    const p = await auth(req);
    const { items } = await d.sandboxes.list(p, req.query, true);
    return items;
  });
  app.get("/v2/sandboxes", async (req: Req, reply) => {
    const p = await auth(req);
    const { items, nextToken } = await d.sandboxes.list(p, req.query);
    if (nextToken) reply.header("x-next-token", nextToken);
    return items;
  });

  app.get("/sandboxes/:id", async (req: Req) => d.sandboxes.get(await auth(req), req.params.id!));
  app.delete("/sandboxes/:id", async (req: Req, reply) => {
    await d.sandboxes.kill(await auth(req), req.params.id!);
    reply.code(204);
  });
  app.post("/sandboxes/:id/timeout", async (req: Req, reply) => {
    await d.sandboxes.setTimeout(await auth(req), req.params.id!, body(req));
    reply.code(204);
  });
  app.post("/sandboxes/:id/refreshes", async (req: Req, reply) => {
    const duration = body(req).duration;
    await d.sandboxes.setTimeout(await auth(req), req.params.id!, { timeout: typeof duration === "number" ? duration : 60 });
    reply.code(204);
  });
  app.post("/sandboxes/:id/pause", async (req: Req, reply) => {
    await d.sandboxes.pause(await auth(req), req.params.id!);
    reply.code(204);
  });
  const connect = async (req: Req, reply: import("fastify").FastifyReply) => {
    const out = await d.sandboxes.connect(await auth(req), req.params.id!, body(req));
    reply.code(out.status);
    return out.body;
  };
  app.post("/v2/sandboxes/:id/connect", connect);
  app.post("/sandboxes/:id/connect", connect);
  app.post("/sandboxes/:id/resume", async (req: Req, reply) => {
    const out = await d.sandboxes.connect(await auth(req), req.params.id!, body(req));
    reply.code(201);
    return out.body;
  });
  app.get("/sandboxes/:id/metrics", async (req: Req) => d.sandboxes.metrics(await auth(req), req.params.id!));
  app.put("/sandboxes/:id/network", async (req: Req, reply) => {
    await d.sandboxes.updateNetwork(await auth(req), req.params.id!, body(req));
    reply.code(204);
  });
  app.get("/sandboxes/:id/logs", async (req: Req) => {
    await d.sandboxes.get(await auth(req), req.params.id!);
    return { logs: [], logEntries: [] };
  });
  app.get("/v2/sandboxes/:id/logs", async (req: Req) => {
    await d.sandboxes.get(await auth(req), req.params.id!);
    return { logs: [], hasMore: false };
  });
  for (const path of ["/sandboxes/:id/snapshots", "/sandboxes/:id/fork"]) {
    app.post(path, async (req: Req) => {
      await auth(req);
      throw new ApiError(501, "snapshots and forks are not supported by this deployment yet; use pause and connect");
    });
  }

  // ---- templates -----------------------------------------------------------
  app.get("/templates", async (req: Req) => (await d.templates.list((await auth(req)).teamId)).map(templateSummary));

  app.get("/templates/aliases/:alias", async (req: Req) => {
    const p = await auth(req);
    const name = req.params.alias!.toLowerCase();
    const all = await d.store.listAllTemplates();
    const match = all.find((t) => t.names.includes(name) && (t.teamId === null || t.teamId === p.teamId));
    if (match) return { templateID: match.templateId, public: match.teamId === null };
    if (all.some((t) => t.names.includes(name))) throw forbidden(`template '${name}' belongs to another team`);
    throw notFound(`template '${name}' not found`);
  });

  app.delete("/templates/:id", async (req: Req, reply) => {
    const p = await auth(req);
    const t = await d.templates.resolve(p.teamId, req.params.id!);
    if (!t) throw notFound(`template ${req.params.id} not found`);
    await d.templates.delete(p, t.templateId);
    reply.code(204);
  });

  // Template.build(): request a build, then start it with fromImage.
  app.post("/v3/templates", async (req: Req, reply) => {
    const p = await auth(req);
    const b = body(req);
    const rawName = typeof b.name === "string" ? b.name : typeof b.alias === "string" ? b.alias : "";
    const name = rawName.slice(rawName.lastIndexOf("/") + 1).split(":")[0]!.toLowerCase();
    if (!name) throw badRequest("name is required");
    const pending = await d.templates.reserveBuild(p, {
      name,
      cpuCount: typeof b.cpuCount === "number" ? b.cpuCount : undefined,
      memoryMB: typeof b.memoryMB === "number" ? b.memoryMB : undefined,
    });
    reply.code(202);
    return {
      templateID: pending.templateId,
      buildID: pending.buildId,
      public: false,
      names: [name],
      tags: Array.isArray(b.tags) ? b.tags : [],
      aliases: [name],
    };
  });

  app.get("/templates/:id/files/:hash", async (req: Req, reply) => {
    await auth(req);
    // COPY steps are rejected when the build starts; nothing to upload.
    reply.code(201);
    return { present: true };
  });

  app.post("/v2/templates/:id/builds/:buildId", async (req: Req, reply) => {
    const p = await auth(req);
    const b = body(req);
    const { envVars, workdir } = interpretSteps(b.steps);
    let image = typeof b.fromImage === "string" ? b.fromImage : undefined;
    if (!image && typeof b.fromTemplate === "string") {
      const base = await d.templates.resolve(p.teamId, b.fromTemplate);
      if (!base) throw notFound(`template '${b.fromTemplate}' not found`);
      image = base.image;
      Object.assign(envVars, { ...base.envVars, ...envVars });
    }
    let registry: { username: string; password: string } | undefined;
    const reg = b.fromImageRegistry as { type?: string; username?: string; password?: string } | undefined;
    if (reg?.type === "registry" && reg.username && reg.password) registry = { username: reg.username, password: reg.password };
    else if (reg && reg.type !== undefined) throw badRequest(`fromImageRegistry type ${reg.type} is not supported; push the image to your stack's ECR repository`);
    await d.templates.startReservedBuild(p, req.params.id!, req.params.buildId!, {
      image: image ?? "e2bdev/base",
      envVars,
      defaultWorkdir: workdir,
      startCmd: typeof b.startCmd === "string" ? b.startCmd : undefined,
      readyCmd: typeof b.readyCmd === "string" ? b.readyCmd : undefined,
      registry,
    });
    reply.code(202);
  });

  // Legacy (v1 SDK/CLI) trigger with no body: nothing to do but acknowledge.
  app.post("/templates/:id/builds/:buildId", async (req: Req, reply) => {
    await auth(req);
    reply.code(202);
  });

  app.get("/templates/:id/builds/:buildId/status", async (req: Req) => {
    const p = await auth(req);
    const build = await d.store.getBuild(req.params.buildId!);
    const template = build && (await d.store.getTemplate(build.templateId));
    if (!build || !template || (template.teamId !== null && template.teamId !== p.teamId)) throw notFound("build not found");
    const offset = Math.max(0, Number(req.query.logsOffset ?? 0) || 0);
    const lines = build.logs.slice(offset, offset + 100);
    const status = build.status === "building" ? (build.hostId ? "building" : "waiting") : build.status;
    return {
      templateID: template.templateId,
      buildID: build.buildId,
      status,
      logs: lines,
      logEntries: lines.map((message) => ({ timestamp: build.updatedAt, message, level: "info" })),
      ...(build.status === "error" ? { reason: { message: build.error ?? "build failed" } } : {}),
    };
  });
}
