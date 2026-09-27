import { describe, expect, it } from "vitest";

import { WeftAdmin, WeftApiError, e2bEnvironment } from "../src/index.js";

function fakeFetch(handler: (url: string, init: RequestInit) => Response) {
  const calls: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return handler(url, init);
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe("e2bEnvironment", () => {
  it("builds the three variables the E2B SDKs read", () => {
    expect(e2bEnvironment({ apiUrl: "https://api.sandbox.example.com/", domain: "sandbox.example.com", apiKey: "weft_sk_x" })).toEqual({
      E2B_API_URL: "https://api.sandbox.example.com",
      E2B_DOMAIN: "sandbox.example.com",
      E2B_API_KEY: "weft_sk_x",
    });
    expect(() => e2bEnvironment({ apiUrl: "api.example.com", domain: "d", apiKey: "k" })).toThrow(/https/);
    expect(() => e2bEnvironment({ apiUrl: "https://a", domain: "https://d", apiKey: "k" })).toThrow(/host name/);
  });
});

describe("WeftAdmin", () => {
  it("sends the API key and JSON bodies", async () => {
    const { f, calls } = fakeFetch(() => new Response(JSON.stringify({ team: { teamId: "team_1" }, apiKey: { keyId: "k", key: "s" } }), { status: 201 }));
    const admin = new WeftAdmin({ apiUrl: "https://api.x/", apiKey: "weft_sk_admin", fetch: f });
    const out = await admin.teams.create("ml platform");
    expect(out.team.teamId).toBe("team_1");
    expect(calls[0]!.url).toBe("https://api.x/weft/v1/teams");
    expect((calls[0]!.init.headers as Record<string, string>)["x-api-key"]).toBe("weft_sk_admin");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ name: "ml platform" });
  });

  it("encodes path segments", async () => {
    const { f, calls } = fakeFetch(() => new Response(null, { status: 204 }));
    const admin = new WeftAdmin({ apiUrl: "https://api.x", apiKey: "k", fetch: f });
    await admin.apiKeys.revoke("team/../x", "key 1");
    expect(calls[0]!.url).toBe("https://api.x/weft/v1/teams/team%2F..%2Fx/api-keys/key%201");
  });

  it("surfaces API errors with their status and message", async () => {
    const { f } = fakeFetch(() => new Response(JSON.stringify({ code: 403, message: "this operation needs an admin key" }), { status: 403 }));
    const admin = new WeftAdmin({ apiUrl: "https://api.x", apiKey: "k", fetch: f });
    const err = await admin.teams.list().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WeftApiError);
    expect((err as WeftApiError).status).toBe(403);
    expect((err as Error).message).toContain("needs an admin key");
  });

  it("waits for template builds and streams new log lines once", async () => {
    let n = 0;
    const { f } = fakeFetch(() => {
      n++;
      const base = { templateId: "t1", latestBuildId: "b2", logs: ["pulling", "unpacking", "ready"].slice(0, n) };
      return new Response(JSON.stringify(n < 3 ? { ...base, status: "building", buildId: "b1" } : { ...base, status: "ready", buildId: "b2" }));
    });
    const admin = new WeftAdmin({ apiUrl: "https://api.x", apiKey: "k", fetch: f });
    const lines: string[] = [];
    const t = await admin.templates.waitUntilReady("t1", { intervalMs: 1, onLog: (l) => lines.push(l) });
    expect(t.buildId).toBe("b2");
    expect(lines).toEqual(["pulling", "unpacking", "ready"]);
  });

  it("reports failed builds", async () => {
    const { f } = fakeFetch(() => new Response(JSON.stringify({ templateId: "t", status: "error", error: "image not found", buildId: null, latestBuildId: "b" })));
    const admin = new WeftAdmin({ apiUrl: "https://api.x", apiKey: "k", fetch: f });
    await expect(admin.templates.waitUntilReady("t", { intervalMs: 1 })).rejects.toThrow(/image not found/);
  });

  it("requires a URL and key", () => {
    const saved = { ...process.env };
    delete process.env.WEFT_API_URL;
    delete process.env.E2B_API_URL;
    expect(() => new WeftAdmin({ apiKey: "k" })).toThrow(/apiUrl/);
    process.env = saved;
  });
});
