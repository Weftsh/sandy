import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  CHECK_FIELDS,
  buildCheckBody,
  checkoutMarketplaceLicense,
  evaluateLicense,
  generateSigningKeyPair,
  issueLicenseKey,
  localSigner,
  sendLicenseCheck,
  trustedKeysFromPem,
  verifyLicenseKey,
  type LicensePayload,
} from "../src/index.js";

const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
const trusted = trustedKeysFromPem({ "test-1": publicKeyPem });
const signer = localSigner(createPrivateKey(privateKeyPem));

function payload(overrides: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1,
    kid: "test-1",
    lid: "lic_test_123",
    entity: "Example Corp",
    tier: "team",
    accounts: ["111122223333"],
    maxConcurrent: 50,
    mode: "online",
    iat: "2026-10-01T00:00:00.000Z",
    exp: "2027-10-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("license keys", () => {
  it("round-trips a signed key", async () => {
    const key = await issueLicenseKey(payload(), signer);
    expect(key.startsWith("weft_lic_v1.")).toBe(true);
    const result = verifyLicenseKey(key, trusted);
    expect(result).toEqual({ ok: true, license: payload() });
  });

  it("rejects a key whose payload was edited", async () => {
    const key = await issueLicenseKey(payload(), signer);
    const [prefix, , sig] = key.split(".");
    const forged = Buffer.from(JSON.stringify(payload({ tier: "enterprise", maxConcurrent: null }))).toString(
      "base64url",
    );
    const result = verifyLicenseKey(`${prefix}.${forged}.${sig}`, trusted);
    expect(result).toMatchObject({ ok: false, reason: "bad_signature" });
  });

  it("rejects a key signed by an untrusted key", async () => {
    const other = generateKeyPairSync("ed25519").privateKey;
    const key = await issueLicenseKey(payload(), localSigner(other));
    expect(verifyLicenseKey(key, trusted)).toMatchObject({ ok: false, reason: "bad_signature" });
    const unknownKid = await issueLicenseKey(payload({ kid: "nope" }), signer);
    expect(verifyLicenseKey(unknownKid, trusted)).toMatchObject({ ok: false, reason: "unknown_signing_key" });
  });

  it("rejects malformed keys without throwing", () => {
    for (const bad of ["", "abc", "weft_lic_v1..", "weft_lic_v1.a.b.c", "other.eyJ9.AA", "weft_lic_v1.@@.@@", "x".repeat(10000)]) {
      expect(verifyLicenseKey(bad, trusted).ok).toBe(false);
    }
  });

  it("refuses to issue invalid payloads", async () => {
    await expect(issueLicenseKey(payload({ accounts: ["123"] }), signer)).rejects.toThrow(/accounts/);
    await expect(issueLicenseKey(payload({ mode: "offline" }), signer)).rejects.toThrow(/offline/);
    await expect(issueLicenseKey(payload({ maxConcurrent: 0 }), signer)).rejects.toThrow(/maxConcurrent/);
    await expect(issueLicenseKey(payload({ exp: "2020-01-01T00:00:00Z" }), signer)).rejects.toThrow(/exp/);
  });

  it("only accepts Ed25519 trusted keys", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" });
    expect(() => trustedKeysFromPem({ rsa: rsa.toString() })).toThrow(/Ed25519/);
  });
});

describe("license status", () => {
  const now = new Date("2027-01-01T00:00:00Z");
  const ok = (p: LicensePayload) => ({ ok: true as const, license: p });

  it("never exposes an allow/deny decision", () => {
    const status = evaluateLicense({ now, concurrentSandboxes: 0 });
    expect(status).not.toHaveProperty("allowed");
    expect(status.state).toBe("unlicensed");
    expect(status.warnings[0]).toMatch(/Sandboxes run normally/);
  });

  it("reports an active license", () => {
    const status = evaluateLicense({
      now,
      key: ok(payload()),
      accountId: "111122223333",
      concurrentSandboxes: 10,
      lastCheckAt: new Date("2026-12-31T12:00:00Z"),
    });
    expect(status).toMatchObject({ state: "active", tier: "team", releaseAccess: true, overCap: false, checkOverdue: false });
    expect(status.warnings).toEqual([]);
  });

  it("warns, but does not block, when over the concurrency cap", () => {
    const status = evaluateLicense({ now, key: ok(payload()), accountId: "111122223333", concurrentSandboxes: 51 });
    expect(status.overCap).toBe(true);
    expect(status.state).toBe("active");
    expect(status.warnings.join(" ")).toMatch(/keep launching/);
  });

  it("flags an account the key does not cover", () => {
    const status = evaluateLicense({ now, key: ok(payload()), accountId: "999988887777", concurrentSandboxes: 0 });
    expect(status).toMatchObject({ state: "invalid", accountCovered: false, releaseAccess: false });
  });

  it("walks through expiring, lapsed-in-grace and lapsed", () => {
    const p = payload({ exp: "2027-01-20T00:00:00Z" });
    expect(evaluateLicense({ now, key: ok(p), concurrentSandboxes: 0 }).state).toBe("expiring");
    const day10 = evaluateLicense({ now: new Date("2027-01-30T00:00:00Z"), key: ok(p), concurrentSandboxes: 0 });
    expect(day10).toMatchObject({ state: "lapsed", releaseAccess: true });
    const day31 = evaluateLicense({ now: new Date("2027-02-20T00:00:00Z"), key: ok(p), concurrentSandboxes: 0 });
    expect(day31).toMatchObject({ state: "lapsed", releaseAccess: false });
  });

  it("warns only after seven days without a successful check", () => {
    const base = { now, key: ok(payload()), concurrentSandboxes: 0 };
    expect(evaluateLicense({ ...base, lastCheckAt: new Date("2026-12-26T00:00:00Z") }).checkOverdue).toBe(false);
    expect(evaluateLicense({ ...base, lastCheckAt: new Date("2026-12-24T23:00:00Z") }).checkOverdue).toBe(true);
    expect(evaluateLicense({ ...base, installedAt: new Date("2026-12-30T00:00:00Z") }).checkOverdue).toBe(false);
  });

  it("does not expect checks from offline keys", () => {
    const status = evaluateLicense({
      now,
      key: ok(payload({ tier: "enterprise", mode: "offline", maxConcurrent: null })),
      installedAt: new Date("2025-01-01T00:00:00Z"),
      concurrentSandboxes: 5000,
    });
    expect(status).toMatchObject({ state: "active", checkOverdue: false, overCap: false });
  });

  it("maps a Marketplace entitlement to enterprise", () => {
    const status = evaluateLicense({
      now,
      marketplace: { ok: true, expiresAt: "2028-01-01T00:00:00Z" },
      concurrentSandboxes: 3,
    });
    expect(status).toMatchObject({ state: "active", tier: "enterprise", source: "marketplace", mode: "marketplace" });
  });
});

describe("daily check", () => {
  it("sends exactly the four documented fields", async () => {
    let sent: unknown;
    const fakeFetch = (async (_url: string, init: RequestInit) => {
      sent = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ status: "active" }), { status: 200 });
    }) as unknown as typeof fetch;
    const extra = { keyId: "lic_1", version: "0.1.0", region: "us-east-1", peakConcurrent: 7, secret: "nope" };
    const out = await sendLicenseCheck(extra, { fetch: fakeFetch });
    expect(out.ok).toBe(true);
    expect(Object.keys(sent as object).sort()).toEqual([...CHECK_FIELDS].sort());
    expect(sent).toEqual({ keyId: "lic_1", version: "0.1.0", region: "us-east-1", peakConcurrent: 7 });
  });

  it("sanitizes the peak concurrency value", () => {
    expect(JSON.parse(buildCheckBody({ keyId: "k", version: "v", region: "r", peakConcurrent: -3.7 })).peakConcurrent).toBe(0);
    expect(JSON.parse(buildCheckBody({ keyId: "k", version: "v", region: "r", peakConcurrent: 12.9 })).peakConcurrent).toBe(12);
  });

  it("retries server errors and never throws", async () => {
    let calls = 0;
    const flaky = (async () => {
      calls++;
      if (calls < 3) return new Response("oops", { status: 503 });
      return new Response(JSON.stringify({ status: "lapsed", notice: "Renew soon" }), { status: 200 });
    }) as unknown as typeof fetch;
    const out = await sendLicenseCheck(
      { keyId: "k", version: "v", region: "r", peakConcurrent: 1 },
      { fetch: flaky, sleep: async () => {} },
    );
    expect(calls).toBe(3);
    expect(out).toMatchObject({ ok: true, response: { status: "lapsed", notice: "Renew soon" } });

    const down = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const failed = await sendLicenseCheck(
      { keyId: "k", version: "v", region: "r", peakConcurrent: 1 },
      { fetch: down, sleep: async () => {} },
    );
    expect(failed).toMatchObject({ ok: false, error: "ECONNREFUSED" });
  });

  it("does not retry client errors and rejects unknown responses", async () => {
    let calls = 0;
    const notFound = (async () => {
      calls++;
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    await sendLicenseCheck({ keyId: "k", version: "v", region: "r", peakConcurrent: 1 }, { fetch: notFound, sleep: async () => {} });
    expect(calls).toBe(1);
    const weird = (async () => new Response(JSON.stringify({ status: "great" }))) as unknown as typeof fetch;
    const out = await sendLicenseCheck(
      { keyId: "k", version: "v", region: "r", peakConcurrent: 1 },
      { fetch: weird, sleep: async () => {}, attempts: 1 },
    );
    expect(out.ok).toBe(false);
  });
});

describe("marketplace", () => {
  it("accepts a granted entitlement", async () => {
    const client = {
      send: async () => ({ EntitlementsAllowed: [{ Name: "Enterprise", Unit: "None" }], Expiration: "2028-01-01T00:00:00Z", LicenseArn: "arn:x" }),
    };
    const out = await checkoutMarketplaceLicense(client as never, { productSku: "prod-123", entitlementName: "Enterprise" }, "tok");
    expect(out).toEqual({ ok: true, expiresAt: "2028-01-01T00:00:00.000Z", licenseArn: "arn:x" });
  });

  it("reports failures without throwing", async () => {
    const denied = {
      send: async () => {
        throw Object.assign(new Error("No entitlements"), { name: "NoEntitlementsAllowedException" });
      },
    };
    const out = await checkoutMarketplaceLicense(denied as never, { productSku: "p", entitlementName: "E" }, "t");
    expect(out).toEqual({ ok: false, detail: "NoEntitlementsAllowedException: No entitlements" });
    const partial = { send: async () => ({ EntitlementsAllowed: [] }) };
    expect((await checkoutMarketplaceLicense(partial as never, { productSku: "p", entitlementName: "E" }, "t")).ok).toBe(false);
  });
});
