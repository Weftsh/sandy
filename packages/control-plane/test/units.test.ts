import { describe, expect, it } from "vitest";

import { DENY_ALL, parsePattern, sandboxPolicy, validatePolicy, type EgressPolicy } from "../src/egress.js";
import { envdAllowed, parseTarget } from "../src/edge/proxy.js";
import { parseMetadataFilter } from "../src/sandboxes/service.js";
import { InternalAuth } from "../src/auth/internal.js";
import { hashKey, newApiKey, newSandboxId, randomId } from "../src/ids.js";
import { ApiError } from "../src/errors.js";
import { ApiKeys } from "../src/auth/apikeys.js";
import { MemoryStore } from "../src/store/memory.js";
import { hostUtilization } from "../src/hosts/registry.js";
import type { Host } from "../src/store/types.js";

const team: EgressPolicy = {
  allow: [{ host: "*.pypi.org" }, { host: "pypi.org" }, { host: "api.github.com" }, { host: "10.20.0.0/16", ports: [5432] }],
  credentials: [{ host: "api.openai.com", header: "authorization", secretId: "openai", format: "Bearer {{secret}}" }],
};

describe("ids", () => {
  it("generates hostname-safe sandbox IDs", () => {
    for (let i = 0; i < 200; i++) expect(newSandboxId()).toMatch(/^[a-z0-9]{20}$/);
    expect(randomId(5)).toHaveLength(5);
    const k = newApiKey();
    expect(k.startsWith("weft_sk_")).toBe(true);
    expect(hashKey(k)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("egress policy validation", () => {
  it("accepts valid policies and rejects bad ones", () => {
    expect(validatePolicy({ allow: [{ host: "*.github.com", ports: [443] }] })).toEqual({ allow: [{ host: "*.github.com", ports: [443] }], credentials: [] });
    const bad = [
      { allow: [{ host: "*.com" }] },
      { allow: [{ host: "a.*.com" }] },
      { allow: [{ host: "x.com", ports: [0] }] },
      { allow: [{ host: "x.com", extra: 1 }] },
      { deny: [] },
      { credentials: [{ host: "*.x.com", header: "a", secretId: "s" }] },
      { credentials: [{ host: "x.com", header: "Host", secretId: "s" }] },
      { credentials: [{ host: "x.com", header: "x-key", secretId: "s", format: "nope" }] },
      { credentials: [{ host: "x.com", header: "x-key", secretId: "s", format: "{{secret}}\r\nx: y" }] },
      "nope",
    ];
    for (const b of bad) expect(() => validatePolicy(b), JSON.stringify(b)).toThrow(ApiError);
  });

  it("parses CIDRs including IPv6", () => {
    expect(parsePattern("10.0.0.0/8")).toMatchObject({ kind: "cidr", family: 4, prefix: 8 });
    expect(parsePattern("2001:db8::/32")).toMatchObject({ kind: "cidr", family: 6, prefix: 32 });
    expect(typeof parsePattern("10.0.0.0/33")).toBe("string");
  });
});

describe("sandbox egress narrowing", () => {
  it("keeps the team policy by default, including when the SDK asks for internet", () => {
    expect(sandboxPolicy(team, {})).toBe(team);
    expect(sandboxPolicy(team, { allowInternetAccess: true })).toBe(team);
    expect(sandboxPolicy(DENY_ALL, { allowInternetAccess: true })).toEqual(DENY_ALL);
  });

  it("denies everything when the SDK turns internet off", () => {
    expect(sandboxPolicy(team, { allowInternetAccess: false })).toEqual(DENY_ALL);
    expect(sandboxPolicy(team, { network: { denyOut: ["0.0.0.0/0"] } })).toEqual(DENY_ALL);
  });

  it("narrows to allowOut entries the team already allows", () => {
    const p = sandboxPolicy(team, { network: { denyOut: ["0.0.0.0/0"], allowOut: ["files.pypi.org", "api.openai.com"] } });
    expect(p.allow).toEqual([{ host: "files.pypi.org" }, { host: "api.openai.com" }]);
    expect(p.credentials.map((c) => c.host)).toEqual(["api.openai.com"]);
  });

  it("refuses allowOut entries that would widen access", () => {
    for (const entry of ["evil.com", "*.github.com", "10.21.0.0/16", "1.1.1.1"]) {
      expect(() => sandboxPolicy(team, { network: { denyOut: ["0.0.0.0/0"], allowOut: [entry] } }), entry).toThrow(/not permitted/);
    }
    const anyPublic: EgressPolicy = { allow: [{ host: "*" }], credentials: [] };
    expect(sandboxPolicy(anyPublic, { network: { denyOut: ["0.0.0.0/0"], allowOut: ["1.1.1.1"] } }).allow).toEqual([{ host: "1.1.1.1" }]);
    expect(() => sandboxPolicy(anyPublic, { network: { denyOut: ["0.0.0.0/0"], allowOut: ["10.0.0.5"] } })).toThrow(/not permitted/);
    expect(() => sandboxPolicy(anyPublic, { network: { denyOut: ["0.0.0.0/0"], allowOut: ["169.254.169.254"] } })).toThrow(/not permitted/);
  });

  it("rejects network features it cannot honor instead of ignoring them", () => {
    expect(() => sandboxPolicy(team, { network: { rules: { "a.com": [] } } })).toThrow(/not supported/);
    expect(() => sandboxPolicy(team, { network: { egressProxy: { address: "x:1" } } })).toThrow(/not supported/);
    expect(() => sandboxPolicy(team, { network: { denyOut: ["8.8.8.8"] } })).toThrow(/denyOut supports only/);
  });
});

describe("edge routing", () => {
  it("routes by host label", () => {
    expect(parseTarget("49983-abc123.sandbox.example.com", {}, "sandbox.example.com")).toEqual({ sandboxId: "abc123", port: 49983 });
    expect(parseTarget("3000-abc123.sandbox.example.com:443", {}, "sandbox.example.com")).toEqual({ sandboxId: "abc123", port: 3000 });
    expect(parseTarget("api.sandbox.example.com", {}, "sandbox.example.com")).toBeUndefined();
    expect(parseTarget("49983-ABC.evil.com", {}, "sandbox.example.com")).toBeUndefined();
    expect(parseTarget("70000-abc.sandbox.example.com", {}, "sandbox.example.com")).toBeUndefined();
    expect(parseTarget("49983-a-b.sandbox.example.com", {}, "sandbox.example.com")).toBeUndefined();
    expect(parseTarget("49983-abc.127-0-0-1.sslip.io:3443", {}, "127-0-0-1.sslip.io:3443")).toEqual({ sandboxId: "abc", port: 49983 });
  });

  it("routes by E2B headers when a single sandbox URL is used", () => {
    expect(parseTarget("127.0.0.1:3001", { "e2b-sandbox-id": "abc", "e2b-sandbox-port": "49983" }, "x.test")).toEqual({ sandboxId: "abc", port: 49983 });
    expect(parseTarget("127.0.0.1:3001", { "e2b-sandbox-id": "abc" }, "x.test")).toEqual({ sandboxId: "abc", port: 49983 });
    expect(parseTarget("127.0.0.1:3001", { "e2b-sandbox-id": "../x" }, "x.test")).toBeUndefined();
  });

  it("only lets clients reach the envd endpoints the SDKs use", () => {
    expect(envdAllowed("POST", "/process.Process/Start")).toBe(true);
    expect(envdAllowed("POST", "/filesystem.Filesystem/WatchDir")).toBe(true);
    expect(envdAllowed("GET", "/files")).toBe(true);
    expect(envdAllowed("GET", "/health")).toBe(true);
    for (const [m, p] of [
      ["POST", "/init"],
      ["POST", "/freeze"],
      ["POST", "/unfreeze"],
      ["POST", "/upgrade"],
      ["GET", "/envs"],
      ["POST", "/files/compose"],
      ["GET", "/process.Process/Start"],
      ["POST", "//init"],
      ["POST", "/INIT"],
      ["POST", "/files%2F..%2Finit"],
    ] as const) {
      expect(envdAllowed(m, new URL(p, "http://x").pathname), `${m} ${p}`).toBe(false);
    }
    // Dot segments are resolved before the check, so this is /init.
    expect(envdAllowed("POST", new URL("/files/../init", "http://x").pathname)).toBe(false);
  });
});

describe("metadata filters", () => {
  it("decodes the SDKs' double encoding", () => {
    const pySent = new URLSearchParams({ [encodeURIComponent("user id")]: encodeURIComponent("a&b=c") }).toString();
    expect(parseMetadataFilter(pySent)).toEqual({ "user id": "a&b=c" });
    expect(parseMetadataFilter("env=prod&team=ml")).toEqual({ env: "prod", team: "ml" });
    expect(parseMetadataFilter(undefined)).toEqual({});
  });
});

describe("internal auth", () => {
  const cfg = {
    kind: "aws-iam" as const,
    serverId: "weft-test",
    region: "us-east-1",
    accountId: "111122223333",
    hostRoleName: "weft-host",
    gatewayRoleName: "weft-gateway",
  };
  const signed = (overrides: Record<string, unknown> = {}, headers: Record<string, string> = {}) =>
    `aws-iam ${Buffer.from(
      JSON.stringify({
        method: "POST",
        url: "https://sts.us-east-1.amazonaws.com/",
        body: "Action=GetCallerIdentity&Version=2011-06-15",
        headers: {
          host: "sts.us-east-1.amazonaws.com",
          "content-type": "application/x-www-form-urlencoded; charset=utf-8",
          "x-amz-date": "20260927T120000Z",
          "x-weft-server-id": "weft-test",
          authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260927/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-weft-server-id, Signature=abc",
          ...headers,
        },
        ...overrides,
      }),
    ).toString("base64")}`;
  const sts = (arn: string, calls: string[] = []) =>
    (async (url: string) => {
      calls.push(url);
      return new Response(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>${arn}</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`);
    }) as unknown as typeof fetch;

  it("identifies hosts and the gateway by role", async () => {
    const host = new InternalAuth(cfg, sts("arn:aws:sts::111122223333:assumed-role/weft-host/i-0123456789abcdef0"));
    expect(await host.verify(signed())).toEqual({ kind: "host", hostId: "i-0123456789abcdef0" });
    const gw = new InternalAuth(cfg, sts("arn:aws:sts::111122223333:assumed-role/weft-gateway/3f1c2b"));
    expect(await gw.verify(signed())).toEqual({ kind: "gateway" });
  });

  it("never calls a URL taken from the header", async () => {
    const calls: string[] = [];
    const a = new InternalAuth(cfg, sts("arn:aws:sts::111122223333:assumed-role/weft-host/i-0123456789abcdef0", calls));
    await expect(a.verify(signed({ url: "https://evil.example/" }))).rejects.toThrow(/unexpected signed request/);
    await expect(a.verify(signed({ body: "Action=ListUsers" }))).rejects.toThrow(/unexpected signed request/);
    expect(calls).toEqual([]);
  });

  it("requires the signed server ID and rejects foreign roles and accounts", async () => {
    const ok = sts("arn:aws:sts::111122223333:assumed-role/weft-host/i-0123456789abcdef0");
    const a = new InternalAuth(cfg, ok);
    await expect(a.verify(signed({}, { "x-weft-server-id": "other" }))).rejects.toThrow(/another server/);
    await expect(
      a.verify(signed({}, { authorization: "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=content-type;host;x-amz-date, Signature=abc" })),
    ).rejects.toThrow(/must be signed/);
    await expect(a.verify(signed({}, { "x-evil": "1" }))).rejects.toThrow(/unexpected header/);
    await expect(new InternalAuth(cfg, sts("arn:aws:sts::999988887777:assumed-role/weft-host/i-0123456789abcdef0")).verify(signed())).rejects.toThrow(/another AWS account/);
    await expect(new InternalAuth(cfg, sts("arn:aws:sts::111122223333:assumed-role/admin/i-0123456789abcdef0")).verify(signed())).rejects.toThrow(/may not call/);
    await expect(new InternalAuth(cfg, sts("arn:aws:iam::111122223333:user/alice")).verify(signed())).rejects.toThrow(/assumed IAM role/);
    await expect(new InternalAuth(cfg, sts("arn:aws:sts::111122223333:assumed-role/weft-host/not-an-instance")).verify(signed())).rejects.toThrow(/not an EC2 instance/);
  });

  it("checks dev tokens in constant time and only in dev-token mode", async () => {
    const dev = new InternalAuth({ kind: "dev-token", devToken: "a-long-development-token" });
    expect(await dev.verify("dev-token a-long-development-token")).toEqual({ kind: "dev" });
    await expect(dev.verify("dev-token wrong")).rejects.toThrow();
    await expect(new InternalAuth(cfg).verify("dev-token a-long-development-token")).rejects.toThrow();
    await expect(dev.verify(undefined)).rejects.toThrow(/missing/);
  });
});

describe("bootstrap admin key", () => {
  it("revokes the previous key when the secret is rotated", async () => {
    const store = new MemoryStore();
    const oldKey = newApiKey();
    const newKey = newApiKey();
    await new ApiKeys(store).ensureAdminKey(oldKey);
    // A restart with the rotated secret.
    const keys = new ApiKeys(store);
    await keys.ensureAdminKey(newKey);
    await expect(keys.authenticate({ "x-api-key": newKey })).resolves.toMatchObject({ role: "admin" });
    await expect(keys.authenticate({ "x-api-key": oldKey })).rejects.toThrow();
    // Restarting with the same secret changes nothing.
    await keys.ensureAdminKey(newKey);
    await expect(keys.authenticate({ "x-api-key": newKey })).resolves.toMatchObject({ role: "admin" });
  });
});

describe("host utilization", () => {
  const host = (sandboxes: number, capacity: Host["capacity"], memoryCommittedMib?: number) =>
    ({ sandboxes: Array.from({ length: sandboxes }, (_, i) => ({ sandboxId: `s${i}`, state: "running" })), capacity, memoryCommittedMib }) as Host;

  it("uses the tighter of slots and memory", () => {
    expect(hostUtilization(host(8, { maxSandboxes: 32, vcpus: 8, memoryMib: 16384 }))).toBe(0.25);
    expect(hostUtilization(host(8, { maxSandboxes: 32, vcpus: 8, memoryMib: 16384, memoryBudgetMib: 14336 }, 10752))).toBe(0.75);
    expect(hostUtilization(host(8, { maxSandboxes: 32, vcpus: 8, memoryMib: 16384, memoryBudgetMib: 14336 }, 20000))).toBe(1);
    expect(hostUtilization(host(31, { maxSandboxes: 32, vcpus: 8, memoryMib: 16384 }), 1)).toBe(1);
  });
});
