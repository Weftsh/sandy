/**
 * Control plane integration tests with fake host agents that speak the real
 * host protocol (TLS with a pinned self-signed certificate, bearer token,
 * CONNECT tunnel). Covers the Firecracker code path (snapshots in S3) that
 * the namespace runtime used by the end-to-end suite does not exercise.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildApi } from "../src/api/server.js";
import { ApiKeys } from "../src/auth/apikeys.js";
import { InternalAuth } from "../src/auth/internal.js";
import { Edge, createEdgeServer } from "../src/edge/proxy.js";
import { HostRegistry } from "../src/hosts/registry.js";
import { LicenseService } from "../src/license/service.js";
import { silentLogger } from "../src/log.js";
import { SandboxService } from "../src/sandboxes/service.js";
import { MemoryStore } from "../src/store/memory.js";
import { TemplateService } from "../src/templates/service.js";
import type { ArtifactStore, PendingUpload } from "../src/artifacts.js";
import type { ArtifactObject } from "../src/store/types.js";

const DEV_TOKEN = "integration-test-dev-token";
const DOMAIN = "sandbox.test";

function selfSignedCert(): { cert: string; key: string } {
  const dir = mkdtempSync(join(tmpdir(), "weft-cert-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-subj", "/CN=weft-host-agent", "-addext", "subjectAltName=DNS:weft-host-agent", "-days", "1",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
  ], { stdio: "ignore" });
  return { cert: readFileSync(join(dir, "cert.pem"), "utf8"), key: readFileSync(join(dir, "key.pem"), "utf8") };
}

/** A fake envd: answers /health and streams a Connect response slowly. */
function startFakeEnvd(): Promise<net.Server> {
  const server = http.createServer((req, res) => {
    if (req.url === "/health") {
      res.writeHead(204).end();
      return;
    }
    if (req.url === "/process.Process/Start") {
      res.writeHead(200, { "content-type": "application/connect+json" });
      let n = 0;
      const t = setInterval(() => {
        res.write(`chunk-${n}\n`);
        if (++n === 3) {
          clearInterval(t);
          res.end();
        }
      }, 50);
      return;
    }
    res.writeHead(404).end();
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(server)));
}

interface FakeHost {
  hostId: string;
  runtime: "firecracker" | "namespace";
  token: string;
  cert: string;
  apiPort: number;
  tunnelPort: number;
  sandboxes: Map<string, Record<string, unknown>>;
  requests: { method: string; path: string; body: unknown }[];
  failStarts: number;
  close(): void;
}

async function startFakeHost(hostId: string, runtime: "firecracker" | "namespace", envdPort: number): Promise<FakeHost> {
  const { cert, key } = selfSignedCert();
  const token = `token-${hostId}-0123456789abcdef0123456789abcdef`;
  const host: FakeHost = { hostId, runtime, token, cert, apiPort: 0, tunnelPort: 0, sandboxes: new Map(), requests: [], failStarts: 0, close() {} };
  const api = https.createServer({ cert, key }, (req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      host.requests.push({ method: req.method!, path: req.url!, body });
      if (req.headers.authorization !== `Bearer ${token}`) {
        res.writeHead(401, { "content-type": "application/json" }).end('{"code":401,"message":"bad token"}');
        return;
      }
      const m = /^\/v1\/sandboxes\/([a-z0-9]+)(\/pause)?$/.exec(req.url!);
      const json = (status: number, v: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(v));
      if (m && req.method === "PUT") {
        if (host.failStarts > 0) {
          host.failStarts--;
          return json(503, { code: 503, message: "host is full" });
        }
        host.sandboxes.set(m[1]!, body);
        return json(200, { sandboxId: m[1], state: "running", envdVersion: "0.9.0", startedAt: new Date().toISOString() });
      }
      if (/^\/v1\/sandboxes\/[a-z0-9]+\/egress$/.test(req.url!) && req.method === "PUT") return res.writeHead(204).end();
      if (/^\/v1\/templates\/[^/]+$/.test(req.url!) && req.method === "POST") return json(202, {});
      if (/^\/v1\/templates\/[^/]+$/.test(req.url!) && req.method === "DELETE") return res.writeHead(204).end();
      if (m && req.method === "DELETE") {
        host.sandboxes.delete(m[1]!);
        return res.writeHead(204).end();
      }
      if (m && m[2] && req.method === "POST") {
        if (runtime === "namespace") return json(200, { kind: "local" });
        host.sandboxes.delete(m[1]!);
        const art = (name: string) => ({ sha256: name.padEnd(64, "0"), size: 1000, parts: [{ partNumber: 1, etag: `"etag-${name}"` }] });
        return json(200, { kind: "uploaded", rootfs: art("r"), memory: art("m"), vmstate: art("v") });
      }
      json(404, { code: 404, message: "not found" });
    });
  });
  const tunnel = tls.createServer({ cert, key }, (socket) => {
    let buf = Buffer.alloc(0);
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      socket.off("data", onData);
      const head = buf.subarray(0, end).toString();
      const id = /^CONNECT ([a-z0-9]+):\d+ /.exec(head)?.[1];
      if (!head.includes(`Authorization: Bearer ${token}`) || !id || !host.sandboxes.has(id)) {
        socket.end("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
        return;
      }
      const upstream = net.connect(envdPort, "127.0.0.1", () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const rest = buf.subarray(end + 4);
        if (rest.length) upstream.write(rest);
        socket.pipe(upstream).pipe(socket);
      });
      upstream.on("error", () => socket.destroy());
    };
    socket.on("data", onData);
  });
  await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => tunnel.listen(0, "127.0.0.1", r));
  host.apiPort = (api.address() as AddressInfo).port;
  host.tunnelPort = (tunnel.address() as AddressInfo).port;
  host.close = () => {
    api.close();
    tunnel.close();
  };
  return host;
}

class FakeArtifacts {
  deleted: string[] = [];
  completed: string[] = [];
  async beginUpload(prefix: string): Promise<PendingUpload> {
    const target = { kind: "multipart" as const, partSize: 1, partUrls: ["https://s3.test/part1"] };
    return {
      targets: { rootfs: target, memory: target, vmstate: target },
      complete: async (r) => {
        this.completed.push(prefix);
        const obj = (n: string): ArtifactObject => ({ key: `${prefix}/${n}.zst`, sha256: r[n as "rootfs"].sha256, size: r[n as "rootfs"].size });
        return { rootfs: obj("rootfs"), memory: obj("memory"), vmstate: obj("vmstate") };
      },
      abort: async () => {},
    };
  }
  async presign(o: Record<"rootfs" | "memory" | "vmstate", ArtifactObject>) {
    const ref = (a: ArtifactObject) => ({ url: `https://s3.test/${a.key}?sig`, sha256: a.sha256, size: a.size });
    return { rootfs: ref(o.rootfs), memory: ref(o.memory), vmstate: ref(o.vmstate) };
  }
  async delete(objs: (ArtifactObject | undefined)[]) {
    this.deleted.push(...objs.filter((o): o is ArtifactObject => !!o).map((o) => o.key));
  }
}

describe("control plane with fake Firecracker hosts", () => {
  const store = new MemoryStore();
  const hostsRegistry = new HostRegistry(store);
  const artifacts = new FakeArtifacts();
  let api: ReturnType<typeof buildApi>;
  let base: string;
  let edgeBase: string;
  let edgeServer: http.Server;
  let envd: net.Server;
  const hosts: FakeHost[] = [];
  let teamKey = "";
  let adminKey = "";
  let sandboxService: SandboxService;

  beforeAll(async () => {
    envd = await startFakeEnvd();
    const envdPort = (envd.address() as AddressInfo).port;
    hosts.push(await startFakeHost("i-0aaaaaaaaaaaaaaaa", "firecracker", envdPort));
    hosts.push(await startFakeHost("i-0bbbbbbbbbbbbbbbb", "firecracker", envdPort));
    const keys = new ApiKeys(store);
    const templates = new TemplateService(store, hostsRegistry, artifacts as unknown as ArtifactStore, undefined, { vcpus: 2, memoryMib: 512, diskMib: 2048 }, silentLogger);
    const license = new LicenseService(store, { version: "0.1.0", region: "us-east-1", mode: "key", extraPublicKeys: {} }, silentLogger);
    await license.init();
    const sandboxes = (sandboxService = new SandboxService(
      store,
      hostsRegistry,
      templates,
      artifacts as unknown as ArtifactStore,
      license,
      { domain: DOMAIN, defaultTimeoutSec: 300, maxTimeoutSec: 3600, pausedRetentionDays: 30 },
      silentLogger,
    ));
    adminKey = "weft_sk_integration_admin_key_0123456789";
    await keys.ensureAdminKey(adminKey);
    api = buildApi({
      keys,
      store,
      templates,
      sandboxes,
      license,
      hosts: hostsRegistry,
      auth: new InternalAuth({ kind: "dev-token", devToken: DEV_TOKEN }),
      log: silentLogger,
      version: "test",
    });
    await api.listen({ host: "127.0.0.1", port: 0 });
    base = `http://127.0.0.1:${(api.server.address() as AddressInfo).port}`;
    edgeServer = createEdgeServer(new Edge({ store, hosts: hostsRegistry, domain: DOMAIN, log: silentLogger }));
    await new Promise<void>((r) => edgeServer.listen(0, "127.0.0.1", r));
    edgeBase = `http://127.0.0.1:${(edgeServer.address() as AddressInfo).port}`;

    for (const h of hosts) await heartbeat(h, []);
    const team = await call("POST", "/weft/v1/teams", { name: "it" }, adminKey);
    teamKey = team.body.apiKey.key;
    // A ready public template with Firecracker artifacts in "S3".
    const now = new Date().toISOString();
    const obj = (n: string) => ({ key: `templates/tpl/${n}.zst`, sha256: "a".repeat(64), size: 10 });
    await store.putTemplate({
      templateId: "tpl0000000000000000a", teamId: null, names: ["base"], image: "img", buildId: "b1", latestBuildId: "b1", status: "ready",
      cpuCount: 2, memoryMB: 512, diskSizeMB: 2048, envVars: { FROM_TEMPLATE: "1" }, envdVersion: "0.9.0",
      artifacts: { rootfs: obj("rootfs"), memory: obj("memory"), vmstate: obj("vmstate") }, createdAt: now, updatedAt: now,
    });
  });

  afterAll(async () => {
    hosts.forEach((h) => h.close());
    envd.close();
    edgeServer.close();
    await api.close();
  });

  async function call(method: string, path: string, body?: unknown, key = teamKey, headers: Record<string, string> = {}) {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: { "x-api-key": key, ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : undefined, headers: res.headers };
  }

  async function heartbeat(h: FakeHost, sandboxes: string[], templates: string[] = []) {
    const res = await fetch(`${base}/internal/v1/hosts/heartbeat`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-weft-internal-auth": `dev-token ${DEV_TOKEN}` },
      body: JSON.stringify({
        hostId: h.hostId, privateIp: "127.0.0.1", apiPort: h.apiPort, tunnelPort: h.tunnelPort, certPem: h.cert, token: h.token,
        version: "test", runtime: h.runtime, capacity: { maxSandboxes: 10, vcpus: 8, memoryMib: 16384 },
        sandboxes: sandboxes.map((sandboxId) => ({ sandboxId, state: "running" })), templates, draining: false,
      }),
    });
    expect(res.status).toBe(200);
  }

  it("creates a sandbox on a Firecracker host with presigned template artifacts", async () => {
    const res = await call("POST", "/v2/sandboxes", { templateID: "base", envVars: { A: "1" }, metadata: { m: "1" } });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ templateID: "tpl0000000000000000a", alias: "base", envdVersion: "0.9.0", domain: DOMAIN, trafficAccessToken: null });
    expect(res.body.clientID).toBeTruthy();
    const onHost = hosts.find((h) => h.sandboxes.has(res.body.sandboxID))!;
    const start = onHost.sandboxes.get(res.body.sandboxID)!;
    expect(start.envdAccessToken).toBe(res.body.envdAccessToken);
    expect(start.envVars).toEqual({ FROM_TEMPLATE: "1", A: "1" });
    expect((start.templateArtifacts as { rootfs: { url: string } }).rootfs.url).toContain("templates/tpl/rootfs.zst");
    expect(start.egress).toEqual({ allow: [], credentials: [] });
    await call("DELETE", `/sandboxes/${res.body.sandboxID}`);
  });

  it("fails over to another host when one is full", async () => {
    hosts[0]!.failStarts = 5;
    hosts[1]!.failStarts = 0;
    const res = await call("POST", "/v2/sandboxes", { templateID: "base" });
    expect(res.status).toBe(201);
    expect(hosts[1]!.sandboxes.has(res.body.sandboxID)).toBe(true);
    hosts[0]!.failStarts = 0;
    await call("DELETE", `/sandboxes/${res.body.sandboxID}`);
  });

  it("answers 503 when no host has room", async () => {
    hosts.forEach((h) => (h.failStarts = 10));
    const res = await call("POST", "/v2/sandboxes", { templateID: "base" });
    expect(res.status).toBe(503);
    expect(res.body.code).toBe(503);
    hosts.forEach((h) => (h.failStarts = 0));
    expect((await call("GET", "/v2/sandboxes")).body).toEqual([]);
  });

  it("pauses to S3 and resumes from the snapshot", async () => {
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base", timeout: 60 })).body;
    const id = created.sandboxID;
    expect((await call("POST", `/sandboxes/${id}/pause`, {})).status).toBe(204);
    const paused = (await call("GET", `/sandboxes/${id}`)).body;
    expect(paused.state).toBe("paused");
    expect(artifacts.completed.some((p) => p.startsWith(`snapshots/${id}/`))).toBe(true);
    expect(hosts.every((h) => !h.sandboxes.has(id))).toBe(true);
    const again = await call("POST", `/sandboxes/${id}/pause`, {});
    expect(again.status).toBe(409);
    expect(again.body.code).toBe(409);

    const resumed = await call("POST", `/v2/sandboxes/${id}/connect`, { timeout: 120 });
    expect(resumed.status).toBe(201);
    expect(resumed.body.envdAccessToken).toBe(created.envdAccessToken);
    const host = hosts.find((h) => h.sandboxes.has(id))!;
    const start = host.sandboxes.get(id)! as { resume: { kind: string; snapshot: { memory: { url: string } } } };
    expect(start.resume.kind).toBe("remote");
    expect(start.resume.snapshot.memory.url).toContain(`snapshots/${id}/`);
    expect((await call("GET", `/sandboxes/${id}`)).body.state).toBe("running");
    expect(artifacts.deleted.some((k) => k.startsWith(`snapshots/${id}/`))).toBe(true);
    // Connecting to a running sandbox only extends it.
    expect((await call("POST", `/v2/sandboxes/${id}/connect`, {})).status).toBe(200);
    await call("DELETE", `/sandboxes/${id}`);
  });

  it("scopes sandboxes to their team", async () => {
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" })).body;
    const other = (await call("POST", "/weft/v1/teams", { name: "other" }, adminKey)).body.apiKey.key;
    expect((await call("GET", `/sandboxes/${created.sandboxID}`, undefined, other)).status).toBe(404);
    expect((await call("DELETE", `/sandboxes/${created.sandboxID}`, undefined, other)).status).toBe(404);
    expect((await call("GET", "/v2/sandboxes", undefined, other)).body).toEqual([]);
    expect((await call("GET", "/v2/sandboxes", undefined, "not-a-key")).status).toBe(401);
    await call("DELETE", `/sandboxes/${created.sandboxID}`);
  });

  it("streams envd traffic through the edge and the host tunnel", async () => {
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" })).body;
    const res = await fetch(`${edgeBase}/process.Process/Start`, {
      method: "POST",
      headers: { "e2b-sandbox-id": created.sandboxID, "e2b-sandbox-port": "49983", "content-type": "application/connect+json" },
      body: "{}",
    });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    const first = await reader.read();
    // The first chunk arrives before the stream ends: nothing is buffered.
    expect(new TextDecoder().decode(first.value)).toContain("chunk-0");
    let rest = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      rest += new TextDecoder().decode(value);
    }
    expect(rest).toContain("chunk-2");
    const blocked = await fetch(`${edgeBase}/init`, { method: "POST", headers: { "e2b-sandbox-id": created.sandboxID } });
    expect(blocked.status).toBe(404);
    const unknown = await fetch(`${edgeBase}/health`, { headers: { "e2b-sandbox-id": "nosuchsandbox" } });
    expect(unknown.status).toBe(502);
    await call("DELETE", `/sandboxes/${created.sandboxID}`);
  });

  it("drops sandboxes a host no longer reports and stops orphans", async () => {
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" })).body;
    const host = hosts.find((h) => h.sandboxes.has(created.sandboxID))!;
    const record = (await store.getSandbox(created.sandboxID))!;
    await store.updateSandbox({ ...record, startedAt: new Date(Date.now() - 120_000).toISOString(), version: record.version + 1 });
    host.sandboxes.set("orphan000000000000", {});
    await heartbeat(host, ["orphan000000000000"]);
    await new Promise((r) => setTimeout(r, 200));
    expect(await store.getSandbox(created.sandboxID)).toBeUndefined();
    expect(host.sandboxes.has("orphan000000000000")).toBe(false);
  });

  it("leaves a sandbox that is still resuming onto a host alone", async () => {
    // A Firecracker resume from S3 restores the VM before the record names
    // its host; a heartbeat in between reports a sandbox with no record there.
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" })).body;
    const host = hosts.find((h) => h.sandboxes.has(created.sandboxID))!;
    const record = (await store.getSandbox(created.sandboxID))!;
    await store.updateSandbox({ ...record, state: "resuming", hostId: null, version: record.version + 1 });
    await heartbeat(host, [created.sandboxID]);
    await new Promise((r) => setTimeout(r, 200));
    expect(host.sandboxes.has(created.sandboxID)).toBe(true);
    await store.updateSandbox({ ...record, version: record.version + 2 });
    await call("DELETE", `/sandboxes/${created.sandboxID}`);
  });

  it("drops a restarted host's sandboxes at once", async () => {
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" })).body;
    const host = hosts.find((h) => h.sandboxes.has(created.sandboxID))!;
    // Same process, sandbox missing from the heartbeat: still within its grace.
    await heartbeat(host, []);
    await new Promise((r) => setTimeout(r, 200));
    expect(await store.getSandbox(created.sandboxID)).toBeDefined();
    // The agent restarted: a new certificate and no sandboxes.
    const oldCert = host.cert;
    host.cert = selfSignedCert().cert;
    await new Promise((r) => setTimeout(r, 5));
    await heartbeat(host, []);
    await new Promise((r) => setTimeout(r, 200));
    expect(await store.getSandbox(created.sandboxID)).toBeUndefined();
    host.cert = oldCert;
    await heartbeat(host, []);
  });

  it("rejects heartbeats without valid internal credentials", async () => {
    const res = await fetch(`${base}/internal/v1/hosts/heartbeat`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-weft-internal-auth": "dev-token wrong" },
      body: "{}",
    });
    expect(res.status).toBe(401);
    const egress = await fetch(`${base}/internal/v1/sandboxes/x/egress`);
    expect(egress.status).toBe(401);
  });

  it("serves the egress policy to the gateway with the host's address", async () => {
    const team = (await call("POST", "/weft/v1/teams", { name: "egress" }, adminKey)).body;
    await call("PUT", `/weft/v1/teams/${team.team.teamId}/egress`, { allow: [{ host: "pypi.org" }] }, adminKey);
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" }, team.apiKey.key)).body;
    const res = await fetch(`${base}/internal/v1/sandboxes/${created.sandboxID}/egress`, { headers: { "x-weft-internal-auth": `dev-token ${DEV_TOKEN}` } });
    expect(await res.json()).toEqual({ sandboxId: created.sandboxID, hostIp: "127.0.0.1", policy: { allow: [{ host: "pypi.org" }], credentials: [] } });
    await call("DELETE", `/sandboxes/${created.sandboxID}`, undefined, team.apiKey.key);
  });

  it("applies team policy changes to existing sandboxes, failing closed", async () => {
    const team = (await call("POST", "/weft/v1/teams", { name: "revoke" }, adminKey)).body;
    const teamId = team.team.teamId as string;
    const key = team.apiKey.key as string;
    await call("PUT", `/weft/v1/teams/${teamId}/egress`, { allow: [{ host: "pypi.org" }, { host: "api.github.com" }] }, adminKey);
    const wide = (await call("POST", "/v2/sandboxes", { templateID: "base" }, key)).body;
    const narrow = (await call("POST", "/v2/sandboxes", { templateID: "base", network: { denyOut: ["0.0.0.0/0"], allowOut: ["pypi.org"] } }, key)).body;
    const policyOf = async (id: string) =>
      ((await (await fetch(`${base}/internal/v1/sandboxes/${id}/egress`, { headers: { "x-weft-internal-auth": `dev-token ${DEV_TOKEN}` } })).json()) as { policy: unknown }).policy;
    expect(await policyOf(narrow.sandboxID)).toEqual({ allow: [{ host: "pypi.org" }], credentials: [] });

    for (const h of hosts) h.requests.length = 0;
    await call("PUT", `/weft/v1/teams/${teamId}/egress`, { allow: [{ host: "api.github.com" }] }, adminKey);
    expect(await policyOf(wide.sandboxID)).toEqual({ allow: [{ host: "api.github.com" }], credentials: [] });
    // pypi.org is no longer allowed, so the narrowed sandbox loses everything.
    expect(await policyOf(narrow.sandboxID)).toEqual({ allow: [], credentials: [] });
    const pushed = hosts.flatMap((h) => h.requests).filter((r) => r.method === "PUT" && r.path.endsWith("/egress"));
    expect(pushed.map((r) => r.path).sort()).toEqual([`/v1/sandboxes/${narrow.sandboxID}/egress`, `/v1/sandboxes/${wide.sandboxID}/egress`].sort());
    for (const id of [wide.sandboxID, narrow.sandboxID]) await call("DELETE", `/sandboxes/${id}`, undefined, key);
  });

  it("makes admins choose which team owns a template", async () => {
    const x = (await call("POST", "/weft/v1/teams", { name: "owner-x" }, adminKey)).body;
    const y = (await call("POST", "/weft/v1/teams", { name: "owner-y" }, adminKey)).body;
    const build = (body: Record<string, unknown>, key = adminKey) => call("POST", "/weft/v1/templates", { image: "img", ...body }, key);

    const unowned = await build({ name: "t-unowned" });
    expect(unowned.status).toBe(400);
    expect(unowned.body.message).toMatch(/--team/);
    expect((await build({ name: "t-missing", teamId: "team_missing" })).status).toBe(404);
    expect((await build({ name: "t-both", teamId: x.team.teamId, public: true })).status).toBe(400);
    expect((await build({ name: "t-other", teamId: x.team.teamId }, y.apiKey.key)).status).toBe(403);

    const forX = await build({ name: "t-for-x", teamId: x.team.teamId });
    expect(forX.status).toBe(202);
    expect(forX.body).toMatchObject({ teamId: x.team.teamId, public: false });
    const own = await build({ name: "t-own" }, y.apiKey.key);
    expect(own.body).toMatchObject({ teamId: y.team.teamId, public: false });
    const names = async (key: string) => ((await call("GET", "/templates", undefined, key)).body as { names: string[] }[]).flatMap((t) => t.names);
    expect(await names(x.apiKey.key)).toContain("t-for-x");
    expect(await names(y.apiKey.key)).not.toContain("t-for-x");
  });

  it("asks hosts to evict template builds nothing references", async () => {
    const created = (await call("POST", "/v2/sandboxes", { templateID: "base" })).body;
    const host = hosts.find((h) => h.sandboxes.has(created.sandboxID))!;
    const record = (await store.getSandbox(created.sandboxID))!;
    await store.updateSandbox({ ...record, buildId: "b-old-in-use", version: record.version + 1 });
    await heartbeat(host, [created.sandboxID], ["b1", "b-old-in-use", "b-deleted"]);
    host.requests.length = 0;
    await sandboxService.evictStaleBuilds();
    const deletes = host.requests.filter((r) => r.method === "DELETE" && r.path.startsWith("/v1/templates/")).map((r) => r.path);
    expect(deletes).toEqual(["/v1/templates/b-deleted"]);
    await call("DELETE", `/sandboxes/${created.sandboxID}`);
  });

  it("records why an SDK template build was refused", async () => {
    const reserved = (await call("POST", "/v3/templates", { name: "refused-steps", cpuCount: 1, memoryMB: 512 })).body;
    const refused = await call("POST", `/v2/templates/${reserved.templateID}/builds/${reserved.buildID}`, {
      fromImage: "img",
      steps: [{ type: "RUN", args: ["echo hi"] }],
    });
    expect(refused.status).toBe(400);
    const status = (await call("GET", `/templates/${reserved.templateID}/builds/${reserved.buildID}/status`)).body;
    expect(status.status).toBe("error");
    expect(JSON.stringify(status)).toMatch(/RUN steps are not supported/);
  });

  it("returns E2B-shaped errors", async () => {
    const res = await call("POST", "/v2/sandboxes", { templateID: "missing" });
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ code: 404, message: "template 'missing' not found" });
    const bad = await fetch(`${base}/v2/sandboxes`, { method: "POST", headers: { "x-api-key": teamKey, "content-type": "application/json" }, body: "{not json" });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { code: number }).code).toBe(400);
    const empty = await fetch(`${base}/sandboxes/abc/pause`, { method: "POST", headers: { "x-api-key": teamKey, "content-type": "application/json" } });
    expect(empty.status).toBe(404);
  });

  it("rejects oversized or malformed metadata and environment variables", async () => {
    for (const body of [
      { envVars: { BIG: "x".repeat(200 * 1024) } },
      { metadata: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`k${i}`, "v".repeat(1024)])) },
      { envVars: { "A=B": "1" } },
      { envVars: { "": "1" } },
    ]) {
      const res = await call("POST", "/v2/sandboxes", { templateID: "base", ...body });
      expect(res.status).toBe(400);
    }
  });

  it("rejects options it cannot honor instead of ignoring them", async () => {
    for (const body of [{ autoPause: true, autoResume: { enabled: true } }, { mcp: {} }, { volumeMounts: [{ name: "v", path: "/data" }] }]) {
      const res = await call("POST", "/v2/sandboxes", { templateID: "base", ...body });
      expect(res.status).toBe(400);
      expect((res.body as { code: number }).code).toBe(400);
    }
  });
});
