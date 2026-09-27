import { createPrivateKey } from "node:crypto";

import { describe, expect, it } from "vitest";
import { generateSigningKeyPair, issueLicenseKey, localSigner, type LicensePayload } from "@weftsh/sandbox-license";

import { LicenseService } from "../src/license/service.js";
import { silentLogger } from "../src/log.js";
import { MemoryStore } from "../src/store/memory.js";

const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
const signer = localSigner(createPrivateKey(privateKeyPem));

function payload(overrides: Partial<LicensePayload> = {}): LicensePayload {
  const now = Date.now();
  return {
    v: 1,
    kid: "dev-1",
    lid: "lic_team_42",
    entity: "Example Corp",
    tier: "team",
    accounts: [],
    maxConcurrent: 2,
    mode: "online",
    iat: new Date(now - 86_400_000).toISOString(),
    exp: new Date(now + 365 * 86_400_000).toISOString(),
    ...overrides,
  };
}

function service(fetchImpl?: typeof fetch, store = new MemoryStore(), configuredKey?: string) {
  const svc = new LicenseService(
    store,
    {
      version: "0.1.0",
      region: "eu-west-1",
      mode: "key",
      configuredKey,
      extraPublicKeys: { "dev-1": publicKeyPem },
      fetch: fetchImpl,
      endpoint: "https://license.test/v1/check",
      sleep: async () => {},
    },
    silentLogger,
  );
  return { store, svc };
}

describe("license service", () => {
  it("installs a signed key and reports it active", async () => {
    const { svc } = service();
    await svc.init();
    expect((await svc.status()).state).toBe("unlicensed");
    const status = await svc.installKey(await issueLicenseKey(payload(), signer));
    expect(status).toMatchObject({ state: "active", tier: "team", licenseId: "lic_team_42", maxConcurrent: 2 });
  });

  it("keeps an API-installed key until the configured key changes", async () => {
    const store = new MemoryStore();
    const fromStack = await issueLicenseKey(payload({ lid: "lic_stack" }), signer);
    const fromApi = await issueLicenseKey(payload({ lid: "lic_api" }), signer);
    const first = service(undefined, store, fromStack).svc;
    await first.init();
    expect((await first.status()).licenseId).toBe("lic_stack");
    await first.installKey(fromApi);

    const restarted = service(undefined, store, fromStack).svc;
    await restarted.init();
    expect((await restarted.status()).licenseId).toBe("lic_api");

    const renewed = await issueLicenseKey(payload({ lid: "lic_renewed" }), signer);
    const updated = service(undefined, store, renewed).svc;
    await updated.init();
    expect((await updated.status()).licenseId).toBe("lic_renewed");
  });

  it("rejects keys that do not verify", async () => {
    const { svc } = service();
    const other = localSigner(createPrivateKey(generateSigningKeyPair().privateKeyPem));
    await expect(svc.installKey(await issueLicenseKey(payload(), other))).rejects.toThrow(/rejected/);
    await expect(svc.installKey("garbage")).rejects.toThrow(/rejected/);
  });

  it("tracks peak concurrency and warns over the cap without blocking", async () => {
    const { svc } = service();
    await svc.installKey(await issueLicenseKey(payload(), signer));
    await svc.recordConcurrency(3);
    const status = await svc.status();
    expect(status.overCap).toBe(true);
    expect(status.peakThisMonth).toBe(3);
    expect(status.monthlyPeaks).toEqual({ [new Date().toISOString().slice(0, 7)]: 3 });
    expect(status).not.toHaveProperty("allowed");
  });

  it("sends exactly the documented fields in the daily check", async () => {
    const bodies: unknown[] = [];
    const fakeFetch = (async (_url: string, init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body)));
      return new Response(JSON.stringify({ status: "active", notice: "Renewal due in 60 days" }));
    }) as unknown as typeof fetch;
    const { svc } = service(fakeFetch);
    await svc.installKey(await issueLicenseKey(payload(), signer));
    await svc.recordConcurrency(2);
    await svc.runCheck();
    expect(bodies).toEqual([{ keyId: "lic_team_42", version: "0.1.0", region: "eu-west-1", peakConcurrent: 2 }]);
    const status = await svc.status();
    expect(status.notice).toBe("Renewal due in 60 days");
    expect(status.checkOverdue).toBe(false);
  });

  it("never checks in with offline keys", async () => {
    let called = false;
    const fakeFetch = (async () => {
      called = true;
      return new Response("{}");
    }) as unknown as typeof fetch;
    const { svc } = service(fakeFetch);
    await svc.installKey(await issueLicenseKey(payload({ tier: "enterprise", mode: "offline", maxConcurrent: null }), signer));
    await svc.runCheck();
    expect(called).toBe(false);
  });

  it("survives an unreachable license endpoint and a lapsed key", async () => {
    const down = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const { svc } = service(down);
    await svc.installKey(await issueLicenseKey(payload({ exp: new Date(Date.now() - 86_400_000).toISOString(), iat: new Date(Date.now() - 400 * 86_400_000).toISOString() }), signer).catch(async () => {
      // A key that is already expired still verifies; installKey only checks the signature.
      throw new Error("expired keys must install");
    }));
    await expect(svc.runCheck()).resolves.toBeUndefined();
    const status = await svc.status();
    expect(status.state).toBe("lapsed");
    expect(status.releaseAccess).toBe(true);
  });
});
