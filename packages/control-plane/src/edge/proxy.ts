/**
 * Edge proxy: routes SDK and user traffic to sandboxes.
 *
 * `https://<port>-<sandboxId>.<domain>` (or, for `E2B_SANDBOX_URL` setups,
 * the `E2b-Sandbox-Id` / `E2b-Sandbox-Port` headers) is forwarded through
 * the host's authenticated tunnel to that port in the sandbox. Responses
 * stream without buffering: envd's Connect streams depend on it.
 *
 * For envd (port 49983) only the endpoints the SDKs use are reachable.
 * envd's internal endpoints (`/init`, `/freeze`, `/upgrade`, ...) would let
 * a caller reset the sandbox's access token or state, so they never pass.
 */
import http from "node:http";
import https from "node:https";
import type { Duplex } from "node:stream";

import { safeEqual, SANDBOX_ID_RE } from "../ids.js";
import type { HostRegistry } from "../hosts/registry.js";
import type { HostClient } from "../hosts/client.js";
import type { Sandbox, Store } from "../store/types.js";
import type { Logger } from "../log.js";

export const ENVD_PORT = 49983;

const ENVD_RPCS = new Set(
  [
    "process.Process/List",
    "process.Process/Connect",
    "process.Process/Start",
    "process.Process/Update",
    "process.Process/StreamInput",
    "process.Process/SendInput",
    "process.Process/SendSignal",
    "process.Process/CloseStdin",
    "filesystem.Filesystem/Stat",
    "filesystem.Filesystem/MakeDir",
    "filesystem.Filesystem/Move",
    "filesystem.Filesystem/ListDir",
    "filesystem.Filesystem/Remove",
    "filesystem.Filesystem/WatchDir",
    "filesystem.Filesystem/CreateWatcher",
    "filesystem.Filesystem/GetWatcherEvents",
    "filesystem.Filesystem/RemoveWatcher",
  ].map((m) => `/${m}`),
);

/** Whether a client may call this envd endpoint. `pathname` must be normalized. */
export function envdAllowed(method: string, pathname: string): boolean {
  if (method === "OPTIONS") return pathname === "/health" || pathname === "/files" || ENVD_RPCS.has(pathname);
  if (pathname === "/health") return method === "GET" || method === "HEAD";
  if (pathname === "/files") return method === "GET" || method === "POST";
  return method === "POST" && ENVD_RPCS.has(pathname);
}

export interface Target {
  sandboxId: string;
  port: number;
}

/** Works out which sandbox and port a request is for. */
export function parseTarget(hostHeader: string | undefined, headers: http.IncomingHttpHeaders, domain: string): Target | undefined {
  // Compare hostnames only: a development domain may carry a port
  // (E2B_DOMAIN=127-0-0-1.sslip.io:3443).
  const host = (hostHeader ?? "").toLowerCase().replace(/:\d+$/, "");
  const suffix = `.${domain.toLowerCase().replace(/:\d+$/, "")}`;
  if (host.endsWith(suffix)) {
    const label = host.slice(0, -suffix.length);
    const m = /^(\d{1,5})-([a-z0-9]{1,64})$/.exec(label);
    if (m) {
      const port = Number(m[1]);
      return port >= 1 && port <= 65535 ? { sandboxId: m[2]!, port } : undefined;
    }
  }
  const id = headers["e2b-sandbox-id"];
  if (typeof id === "string" && SANDBOX_ID_RE.test(id)) {
    const rawPort = headers["e2b-sandbox-port"];
    const port = typeof rawPort === "string" && /^\d{1,5}$/.test(rawPort) ? Number(rawPort) : ENVD_PORT;
    return port >= 1 && port <= 65535 ? { sandboxId: id, port } : undefined;
  }
  return undefined;
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function forwardHeaders(headers: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = {};
  const listed = new Set(
    String(headers.connection ?? "")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  );
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || HOP_BY_HOP.has(k) || listed.has(k)) continue;
    out[k] = v;
  }
  return out;
}

export interface EdgeDeps {
  store: Store;
  hosts: HostRegistry;
  domain: string;
  log: Logger;
}

interface Resolved {
  sandbox: Sandbox;
  client: HostClient;
}

export class Edge {
  private cache = new Map<string, { value: Resolved | null; at: number }>();

  constructor(private d: EdgeDeps) {}

  private async resolve(sandboxId: string): Promise<Resolved | null> {
    const hit = this.cache.get(sandboxId);
    if (hit && Date.now() - hit.at < 1000) return hit.value;
    const sandbox = await this.d.store.getSandbox(sandboxId);
    let value: Resolved | null = null;
    if (sandbox && sandbox.state === "running" && sandbox.hostId) {
      const client = await this.d.hosts.clientFor(sandbox.hostId);
      if (client) value = { sandbox, client };
    }
    if (this.cache.size > 50_000) this.cache.clear();
    this.cache.set(sandboxId, { value, at: Date.now() });
    return value;
  }

  /**
   * Checks a request and returns what to connect to, or the error to send.
   */
  async admit(
    req: http.IncomingMessage,
  ): Promise<{ ok: true; target: Target; resolved: Resolved; path: string } | { ok: false; status: number; body: Record<string, unknown> }> {
    const target = parseTarget(req.headers.host, req.headers, this.d.domain);
    if (!target) return { ok: false, status: 404, body: { code: 404, message: "unknown sandbox host" } };
    const raw = req.url ?? "/";
    if (!raw.startsWith("/")) return { ok: false, status: 400, body: { code: 400, message: "absolute-form request targets are not accepted" } };
    const url = new URL(raw, "http://edge.invalid");
    const path = `${url.pathname}${url.search}`;
    const method = req.method ?? "GET";
    if (target.port === ENVD_PORT && !envdAllowed(method, url.pathname)) {
      return { ok: false, status: 404, body: { code: 404, message: `${method} ${url.pathname} is not available` } };
    }
    const resolved = await this.resolve(target.sandboxId);
    if (!resolved) {
      return { ok: false, status: 502, body: { code: 502, message: "The sandbox was not found", sandboxId: target.sandboxId } };
    }
    const required = resolved.sandbox.trafficAccessToken;
    if (target.port !== ENVD_PORT && required) {
      const presented = req.headers["e2b-traffic-access-token"];
      if (typeof presented !== "string" || !safeEqual(presented, required)) {
        return { ok: false, status: 403, body: { code: 403, message: "this sandbox requires a traffic access token" } };
      }
    }
    return { ok: true, target, resolved, path };
  }

  async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (req.url === "/healthz" && !parseTarget(req.headers.host, req.headers, this.d.domain)) {
      res.writeHead(200, { "content-type": "application/json" }).end('{"status":"ok"}');
      return;
    }
    const admitted = await this.admit(req);
    if (!admitted.ok) {
      sendJson(res, admitted.status, admitted.body);
      return;
    }
    const { target, resolved, path } = admitted;
    let tunnel: Duplex;
    try {
      tunnel = await resolved.client.openTunnel(target.sandboxId, target.port);
    } catch (e) {
      this.cache.delete(target.sandboxId);
      const status = (e as { status?: number }).status;
      sendJson(res, 502, {
        code: 502,
        message: status === 502 ? "The sandbox port is not accepting connections" : "The sandbox was not found",
        sandboxId: target.sandboxId,
      });
      return;
    }
    const upstream = http.request({
      method: req.method,
      path,
      headers: forwardHeaders(req.headers),
      createConnection: () => tunnel as never,
    });
    upstream.on("response", (up) => {
      res.writeHead(up.statusCode ?? 502, forwardHeaders(up.headers));
      res.flushHeaders();
      up.pipe(res);
      up.on("error", () => res.destroy());
    });
    upstream.on("error", (e) => {
      if (!res.headersSent) sendJson(res, 502, { code: 502, message: `sandbox connection failed: ${e.message}`, sandboxId: target.sandboxId });
      else res.destroy();
    });
    res.on("close", () => {
      if (!res.writableFinished) tunnel.destroy();
    });
    req.pipe(upstream);
  }

  /** WebSocket and other upgrades to user ports: forward the handshake, then splice. */
  async upgrade(req: http.IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
    const admitted = await this.admit(req);
    if (!admitted.ok) {
      const body = JSON.stringify(admitted.body);
      socket.end(`HTTP/1.1 ${admitted.status} Error\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`);
      return;
    }
    let tunnel: Duplex;
    try {
      tunnel = await admitted.resolved.client.openTunnel(admitted.target.sandboxId, admitted.target.port);
    } catch {
      socket.end("HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
      return;
    }
    const lines = [`${req.method} ${admitted.path} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i]!;
      const value = req.rawHeaders[i + 1]!;
      if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) continue;
      lines.push(`${name}: ${value}`);
    }
    tunnel.write(`${lines.join("\r\n")}\r\n\r\n`);
    if (head.length > 0) tunnel.write(head);
    tunnel.pipe(socket);
    socket.pipe(tunnel);
    const close = () => {
      tunnel.destroy();
      socket.destroy();
    };
    tunnel.on("error", close);
    socket.on("error", close);
    tunnel.on("close", close);
    socket.on("close", close);
  }
}

function sendJson(res: http.ServerResponse, status: number, body: Record<string, unknown>): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) }).end(text);
}

export function createEdgeServer(edge: Edge, tls?: { certPem: string; keyPem: string }): http.Server {
  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    edge.handle(req, res).catch(() => sendJson(res, 502, { code: 502, message: "edge proxy error" }));
  };
  const server = tls
    ? https.createServer({ cert: tls.certPem, key: tls.keyPem, ALPNProtocols: ["http/1.1"] }, handler)
    : http.createServer(handler);
  server.on("upgrade", (req, socket, head) => {
    edge.upgrade(req, socket, head).catch(() => socket.destroy());
  });
  // Streams (commands, watches) can last hours; the SDKs send keepalives.
  server.requestTimeout = 0;
  server.headersTimeout = 60_000;
  server.keepAliveTimeout = 3_610_000;
  return server;
}
