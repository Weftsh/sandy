import { execFileSync } from "node:child_process";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { CloudFormationCustomResourceEvent } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";

import { caCommonName, generateCa } from "../src/egress-ca/ca.js";
import { objectIdentifier, time, unsignedInteger } from "../src/egress-ca/der.js";
import { handleEgressCa, PHYSICAL_ID, type EgressCaDeps } from "../src/egress-ca/handler.js";

function hasOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("DER helpers", () => {
  it("encodes OIDs, integers and times per X.690 / RFC 5280", () => {
    expect(objectIdentifier("1.2.840.10045.4.3.2").toString("hex")).toBe("06082a8648ce3d040302");
    expect(unsignedInteger(Buffer.from([0x80])).toString("hex")).toBe("02020080");
    expect(unsignedInteger(Buffer.from([0x00, 0x00, 0x01])).toString("hex")).toBe("020101");
    expect(time(new Date("2049-12-31T23:59:59Z")).toString("ascii").slice(2)).toBe("491231235959Z");
    expect(time(new Date("2050-01-01T00:00:00Z"))[0]).toBe(0x18); // GeneralizedTime
  });
});

describe("generateCa", () => {
  const now = new Date("2026-09-27T12:00:00Z");
  const ca = generateCa({ commonName: caCommonName("weft-prod"), now });
  const cert = new X509Certificate(ca.certPem);

  it("produces a self-signed ECDSA P-256 CA certificate", () => {
    expect(cert.ca).toBe(true);
    expect(cert.subject).toBe("O=Weft Sandboxes\nCN=Weft Sandboxes egress CA weft-prod");
    expect(cert.issuer).toBe(cert.subject);
    expect(cert.verify(cert.publicKey)).toBe(true);
    expect(cert.publicKey.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    expect(cert.checkPrivateKey(createPrivateKey(ca.keyPem))).toBe(true);
    expect(cert.serialNumber.toLowerCase()).toBe(ca.serialHex);
    expect(cert.keyUsage ?? []).toEqual([]); // Node lists extended key usage only; checked with OpenSSL below
  });

  it("is valid for ten years from an hour before creation", () => {
    expect(new Date(cert.validFrom).toISOString()).toBe("2026-09-27T11:00:00.000Z");
    expect(new Date(cert.validTo).toISOString()).toBe("2036-09-27T11:00:00.000Z");
    expect(ca.notAfter.getUTCFullYear() - ca.notBefore.getUTCFullYear()).toBe(10);
  });

  it("uses PKCS#8 for the key, which the gateway's rustls/rcgen loader accepts", () => {
    expect(ca.keyPem.startsWith("-----BEGIN PRIVATE KEY-----\n")).toBe(true);
    expect(ca.certPem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
  });

  it("generates a fresh key and serial every time", () => {
    const other = generateCa({ commonName: "x", now });
    expect(other.keyPem).not.toBe(ca.keyPem);
    expect(other.serialHex).not.toBe(ca.serialHex);
    expect(other.serialHex).toMatch(/^[0-7][0-9a-f]{31}$/);
  });

  it("limits the common name to 64 characters", () => {
    expect(caCommonName("s".repeat(128))).toHaveLength(64);
    expect(() => generateCa({ commonName: "" })).toThrow();
  });

  it.runIf(hasOpenssl())("passes OpenSSL's CA checks and can issue a leaf that verifies", () => {
    const dir = mkdtempSync(join(tmpdir(), "weft-ca-test-"));
    try {
      const fresh = generateCa({ commonName: caCommonName("weft-test") });
      writeFileSync(join(dir, "ca.pem"), fresh.certPem);
      writeFileSync(join(dir, "ca.key"), fresh.keyPem);
      const text = execFileSync("openssl", ["x509", "-in", join(dir, "ca.pem"), "-noout", "-text"], { encoding: "utf8" });
      expect(text).toMatch(/Basic Constraints: critical\s+CA:TRUE, pathlen:0/);
      expect(text).toMatch(/Key Usage: critical\s+Certificate Sign, CRL Sign/);
      expect(text).toMatch(/Subject Key Identifier/);
      expect(text).toMatch(/Signature Algorithm: ecdsa-with-SHA256/);
      const run = (args: string[]) => execFileSync("openssl", args, { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key"]);
      run(["req", "-new", "-key", "leaf.key", "-subj", "/CN=api.example.com", "-out", "leaf.csr"]);
      writeFileSync(join(dir, "ext.cnf"), "subjectAltName=DNS:api.example.com\nextendedKeyUsage=serverAuth\n");
      run(["x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-extfile", "ext.cnf", "-out", "leaf.pem"]);
      expect(run(["verify", "-CAfile", "ca.pem", "-purpose", "sslserver", "leaf.pem"])).toMatch(/leaf.pem: OK/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function event(requestType: "Create" | "Update" | "Delete", props: Record<string, unknown>, old?: Record<string, unknown>) {
  const base = {
    ServiceToken: "x",
    ResponseURL: "https://example.com/r",
    StackId: "arn:aws:cloudformation:us-east-1:111122223333:stack/weft/1",
    RequestId: "r",
    LogicalResourceId: "EgressCa",
    ResourceType: "Custom::WeftEgressCa",
    ResourceProperties: { ServiceToken: "x", ...props },
  };
  if (requestType === "Create") return { ...base, RequestType: "Create" } as CloudFormationCustomResourceEvent;
  if (requestType === "Update") {
    return { ...base, RequestType: "Update", PhysicalResourceId: PHYSICAL_ID, OldResourceProperties: { ServiceToken: "x", ...old } } as CloudFormationCustomResourceEvent;
  }
  return { ...base, RequestType: "Delete", PhysicalResourceId: PHYSICAL_ID } as CloudFormationCustomResourceEvent;
}

function fakeDeps() {
  const params = new Map<string, string>();
  const secrets = new Map<string, string>();
  const deps: EgressCaDeps = {
    putSecret: vi.fn(async (arn: string, value: string) => void secrets.set(arn, value)),
    putParameter: vi.fn(async (name: string, value: string) => void params.set(name, value)),
    getParameter: vi.fn(async (name: string) => params.get(name)),
    deleteParameter: vi.fn(async (name: string) => void params.delete(name)),
    generate: vi.fn((cn: string) => generateCa({ commonName: cn })),
  };
  return { deps, params, secrets };
}

const props = {
  SecretArn: "arn:aws:secretsmanager:us-east-1:111122223333:secret:weft-egress-ca-AbCdEf",
  CertParameterName: "/weft/egress-ca-cert",
  StackName: "weft",
};

describe("Custom::WeftEgressCa", () => {
  it("creates the CA secret in the gateway's JSON format and publishes only the certificate", async () => {
    const { deps, params, secrets } = fakeDeps();
    const res = await handleEgressCa(event("Create", props), deps);
    const secret = JSON.parse(secrets.get(props.SecretArn)!);
    expect(Object.keys(secret).sort()).toEqual(["certPem", "keyPem"]);
    expect(res.physicalResourceId).toBe(PHYSICAL_ID);
    expect(res.data?.CertPem).toBe(secret.certPem);
    expect(params.get(props.CertParameterName)).toBe(secret.certPem);
    expect(JSON.stringify(res.data)).not.toContain("PRIVATE KEY");
    expect([...params.values()].join()).not.toContain("PRIVATE KEY");
    expect(new X509Certificate(secret.certPem).subject).toContain("CN=Weft Sandboxes egress CA weft");
  });

  it("keeps the CA across updates", async () => {
    const { deps, params } = fakeDeps();
    await handleEgressCa(event("Create", props), deps);
    const cert = params.get(props.CertParameterName);
    const res = await handleEgressCa(event("Update", props, props), deps);
    expect(res.data?.CertPem).toBe(cert);
    expect(deps.generate).toHaveBeenCalledTimes(1);
    expect(deps.putSecret).toHaveBeenCalledTimes(1);
  });

  it("regenerates when the secret was replaced or the certificate parameter is gone", async () => {
    const { deps, params } = fakeDeps();
    await handleEgressCa(event("Create", props), deps);
    await handleEgressCa(event("Update", { ...props, SecretArn: `${props.SecretArn}2` }, props), deps);
    expect(deps.generate).toHaveBeenCalledTimes(2);
    params.clear();
    await handleEgressCa(event("Update", props, props), deps);
    expect(deps.generate).toHaveBeenCalledTimes(3);
  });

  it("moves the certificate when the parameter name changes", async () => {
    const { deps, params } = fakeDeps();
    await handleEgressCa(event("Create", props), deps);
    const cert = params.get(props.CertParameterName);
    await handleEgressCa(event("Update", { ...props, CertParameterName: "/weft/new" }, props), deps);
    expect(params.get("/weft/new")).toBe(cert);
    expect(params.has(props.CertParameterName)).toBe(false);
  });

  it("removes the parameter on delete and tolerates it being gone", async () => {
    const { deps, params } = fakeDeps();
    await handleEgressCa(event("Create", props), deps);
    await handleEgressCa(event("Delete", props), deps);
    expect(params.size).toBe(0);
    await expect(handleEgressCa(event("Delete", props), deps)).resolves.toBeDefined();
  });
});
