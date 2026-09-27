/** The control plane's HTTP server (Fastify). */
import Fastify, { type FastifyInstance } from "fastify";

import { ApiError } from "../errors.js";
import { registerAdminRoutes, type AdminDeps } from "./admin.js";
import { registerE2BRoutes } from "./e2b.js";
import { registerInternalRoutes, type InternalDeps } from "./internal.js";
import type { Logger } from "../log.js";

export type ApiDeps = AdminDeps & Pick<InternalDeps, "auth"> & { log: Logger; version: string };

export function buildApi(d: ApiDeps): FastifyInstance {
  const app = Fastify({
    logger: false,
    bodyLimit: 2 * 1024 * 1024,
    // Paths like /templates/aliases/team%2Fname are matched on the decoded
    // segment; keep slashes inside a parameter from splitting routes.
    routerOptions: { ignoreTrailingSlash: true, maxParamLength: 512 },
    trustProxy: true,
  });

  // Some SDK calls send `Content-Type: application/json` with no body.
  app.removeContentTypeParser("application/json");
  app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, raw, done) => {
    const text = typeof raw === "string" ? raw : raw.toString("utf8");
    if (text.trim() === "") return done(null, {});
    try {
      done(null, JSON.parse(text));
    } catch {
      done(new ApiError(400, "request body is not valid JSON"), undefined);
    }
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ApiError) {
      void reply.code(err.status).send(err.body());
      return;
    }
    const status = typeof (err as { statusCode?: number }).statusCode === "number" ? (err as { statusCode: number }).statusCode : 500;
    if (status >= 500) d.log.error("request failed", { method: req.method, url: req.url, error: String(err), stack: (err as Error).stack });
    void reply.code(status).send({ code: status, message: status >= 500 ? "internal error" : (err as Error).message });
  });
  app.setNotFoundHandler((req, reply) => {
    void reply.code(404).send({ code: 404, message: `no route for ${req.method} ${req.url.split("?")[0]}` });
  });

  app.addHook("onResponse", async (req, reply) => {
    if (req.url === "/health") return;
    d.log.info("request", { method: req.method, route: req.routeOptions.url, status: reply.statusCode, ms: Math.round(reply.elapsedTime) });
  });

  app.get("/health", async () => ({ status: "ok", version: d.version }));

  registerE2BRoutes(app, d);
  registerAdminRoutes(app, d);
  registerInternalRoutes(app, { auth: d.auth, hosts: d.hosts, sandboxes: d.sandboxes, log: d.log });
  return app;
}
