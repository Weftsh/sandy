/**
 * Internal API for host agents and the egress gateway, authenticated with
 * their IAM roles (see `auth/internal.ts`).
 */
import type { FastifyInstance, FastifyRequest } from "fastify";

import { INTERNAL_AUTH_HEADER, type InternalAuth } from "../auth/internal.js";
import { forbidden, notFound } from "../errors.js";
import { HEARTBEAT_INTERVAL_SEC, type HostRegistry } from "../hosts/registry.js";
import type { SandboxService } from "../sandboxes/service.js";
import type { Logger } from "../log.js";

export interface InternalDeps {
  auth: InternalAuth;
  hosts: HostRegistry;
  sandboxes: SandboxService;
  log: Logger;
}

type Req = FastifyRequest<{ Params: Record<string, string>; Body: unknown }>;

export function registerInternalRoutes(app: FastifyInstance, d: InternalDeps): void {
  const identify = (req: Req) => {
    const h = req.headers[INTERNAL_AUTH_HEADER];
    return d.auth.verify(typeof h === "string" ? h : undefined);
  };

  app.post("/internal/v1/hosts/heartbeat", async (req: Req) => {
    const identity = await identify(req);
    const { host, previous } = await d.hosts.heartbeat(identity, req.body);
    // A new certificate means a new agent process: whatever it does not
    // report from before this moment is gone.
    const restarted = !!previous && previous.certPem !== host.certPem;
    if (!previous || restarted) {
      d.log.info("host registered", { hostId: host.hostId, runtime: host.runtime, version: host.version, privateIp: host.privateIp, restarted });
    }
    void d.sandboxes.reconcileHost(host, Date.now(), restarted).catch((e: unknown) => d.log.warn("reconcile failed", { hostId: host.hostId, error: String(e) }));
    return { heartbeatIntervalSec: HEARTBEAT_INTERVAL_SEC };
  });

  app.get("/internal/v1/sandboxes/:id/egress", async (req: Req) => {
    const identity = await identify(req);
    if (identity.kind === "host") throw forbidden("hosts cannot read egress policies");
    const out = await d.sandboxes.egressFor(req.params.id!);
    if (!out) throw notFound("sandbox is not running");
    return out;
  });
}
