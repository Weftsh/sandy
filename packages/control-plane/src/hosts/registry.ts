/**
 * Host registry and scheduler.
 *
 * Hosts register through their heartbeat. A host is live while its last
 * heartbeat is recent. New sandboxes go to the least-loaded live host with
 * room, preferring hosts that already cache the template.
 */
import { X509Certificate } from "node:crypto";

import { badRequest, forbidden } from "../errors.js";
import type { InternalIdentity } from "../auth/internal.js";
import type { Host, Store } from "../store/types.js";
import { HostClient } from "./client.js";

export const HEARTBEAT_INTERVAL_SEC = 5;
export const HOST_STALE_MS = 30_000;

export interface HeartbeatRequest {
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
}

function validateHeartbeat(raw: unknown): HeartbeatRequest {
  const r = raw as HeartbeatRequest;
  const ok =
    typeof r === "object" &&
    r !== null &&
    typeof r.hostId === "string" &&
    /^[A-Za-z0-9_.-]{1,64}$/.test(r.hostId) &&
    typeof r.privateIp === "string" &&
    typeof r.apiPort === "number" &&
    typeof r.tunnelPort === "number" &&
    typeof r.certPem === "string" &&
    typeof r.token === "string" &&
    r.token.length >= 32 &&
    typeof r.runtime === "string" &&
    typeof r.capacity === "object" &&
    Array.isArray(r.sandboxes) &&
    Array.isArray(r.templates);
  if (!ok) throw badRequest("malformed heartbeat");
  try {
    new X509Certificate(r.certPem);
  } catch {
    throw badRequest("heartbeat certificate is not valid PEM");
  }
  return r;
}

export class HostRegistry {
  private clients = new Map<string, HostClient>();
  private inflight = new Map<string, number>();

  constructor(
    private store: Store,
    private now: () => number = Date.now,
  ) {}

  async heartbeat(identity: InternalIdentity, raw: unknown): Promise<{ host: Host; previous?: Host }> {
    const req = validateHeartbeat(raw);
    if (identity.kind === "gateway") throw forbidden("the gateway cannot register hosts");
    if (identity.kind === "host" && identity.hostId !== req.hostId) {
      throw forbidden("a host can only register as itself");
    }
    const previous = await this.store.getHost(req.hostId);
    const at = new Date(this.now()).toISOString();
    const host: Host = {
      hostId: req.hostId,
      privateIp: req.privateIp,
      apiPort: req.apiPort,
      tunnelPort: req.tunnelPort,
      certPem: req.certPem,
      token: req.token,
      version: req.version,
      runtime: req.runtime,
      capacity: req.capacity,
      sandboxes: req.sandboxes.map((s) => ({ sandboxId: s.sandboxId, state: s.state })),
      templates: req.templates,
      draining: req.draining,
      lastHeartbeatAt: at,
      registeredAt: previous && previous.certPem === req.certPem ? previous.registeredAt : at,
    };
    await this.store.putHost(host);
    return { host, previous };
  }

  isLive(h: Host): boolean {
    return this.now() - Date.parse(h.lastHeartbeatAt) < HOST_STALE_MS;
  }

  async liveHosts(): Promise<Host[]> {
    return (await this.store.listHosts()).filter((h) => this.isLive(h));
  }

  client(host: Host): HostClient {
    const existing = this.clients.get(host.hostId);
    if (existing && existing.host.certPem === host.certPem && existing.host.token === host.token && existing.host.privateIp === host.privateIp) {
      return existing;
    }
    existing?.close();
    const c = new HostClient(host);
    this.clients.set(host.hostId, c);
    return c;
  }

  async clientFor(hostId: string): Promise<HostClient | undefined> {
    const h = await this.store.getHost(hostId);
    return h && this.isLive(h) ? this.client(h) : undefined;
  }

  /**
   * Picks a host for a new sandbox. `requiredHost` pins the choice (templates
   * built by a development host exist only there).
   */
  async pick(opts: { buildId: string; requiredHost?: string; exclude?: Set<string> }): Promise<Host | undefined> {
    const candidates = (await this.liveHosts()).filter(
      (h) =>
        !h.draining &&
        !opts.exclude?.has(h.hostId) &&
        (!opts.requiredHost || h.hostId === opts.requiredHost) &&
        h.sandboxes.length + (this.inflight.get(h.hostId) ?? 0) < h.capacity.maxSandboxes,
    );
    const load = (h: Host) => (h.sandboxes.length + (this.inflight.get(h.hostId) ?? 0)) / Math.max(1, h.capacity.maxSandboxes);
    candidates.sort((a, b) => {
      const cachedA = a.templates.includes(opts.buildId) ? 0 : 1;
      const cachedB = b.templates.includes(opts.buildId) ? 0 : 1;
      return cachedA - cachedB || load(a) - load(b) || a.hostId.localeCompare(b.hostId);
    });
    return candidates[0];
  }

  /** Counts a placement until the host's next heartbeat reports it. */
  reserve(hostId: string): () => void {
    this.inflight.set(hostId, (this.inflight.get(hostId) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.inflight.set(hostId, Math.max(0, (this.inflight.get(hostId) ?? 1) - 1));
    };
  }
}
