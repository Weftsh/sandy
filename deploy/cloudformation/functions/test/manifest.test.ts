import { describe, expect, it } from "vitest";

import {
  base64ToHex,
  checkAmi,
  checkRelease,
  imageDigest,
  parseManifest,
  releaseSignerIdentity,
  type ReleaseManifest,
} from "../src/verify-release/manifest.js";

import { D1, D2, sampleManifest, ZIP_B64, ZIP_HEX } from "./helpers.js";

const bytes = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

describe("releaseSignerIdentity", () => {
  it("pins the repository, workflow and tag", () => {
    expect(releaseSignerIdentity("1.2.3")).toEqual({
      subjectAlternativeName: "https://github.com/Weftsh/sandy/.github/workflows/release.yml@refs/tags/v1.2.3",
      issuer: "https://token.actions.githubusercontent.com",
    });
  });

  it("rejects versions that could smuggle a different ref", () => {
    for (const bad of ["", "1.2", "v1.2.3", "1.2.3@refs/heads/main", "1.2.3 ", "../1.2.3"]) {
      expect(() => releaseSignerIdentity(bad)).toThrow(/invalid release version/);
    }
    expect(releaseSignerIdentity("1.2.3-rc.1").subjectAlternativeName).toMatch(/@refs\/tags\/v1\.2\.3-rc\.1$/);
  });
});

describe("parseManifest", () => {
  it("parses a valid manifest", () => {
    const m = parseManifest(bytes(sampleManifest()));
    expect(m.version).toBe("1.2.3");
    expect(m.amis["us-east-1"]).toBe("ami-0123456789abcdef0");
    expect(m.images["control-plane"]?.digest).toBe(D1);
    expect(m.artifacts["functions/egress-ca.zip"]?.sha256).toBe(ZIP_HEX);
  });

  it.each([
    ["not JSON", new TextEncoder().encode("{")],
    ["an array", bytes([])],
    ["a wrong schema version", bytes(sampleManifest({ schemaVersion: 2 }))],
    ["another product", bytes(sampleManifest({ product: "other" }))],
    ["a bad version", bytes(sampleManifest({ version: "latest" }))],
    ["a bad AMI", bytes(sampleManifest({ amis: { "us-east-1": "ami-xyz" } }))],
    ["a bad region", bytes(sampleManifest({ amis: { "US-EAST-1": "ami-0123456789abcdef0" } }))],
    ["a tag instead of a digest", bytes(sampleManifest({ images: { "control-plane": { repository: "x", digest: "latest" } } }))],
    ["a bad artifact hash", bytes(sampleManifest({ artifacts: { "a.zip": { sha256: "zz" } } }))],
    ["no images", bytes(sampleManifest({ images: undefined }))],
  ])("rejects %s", (_, input) => {
    expect(() => parseManifest(input)).toThrow();
  });

  it("rejects invalid UTF-8", () => {
    expect(() => parseManifest(new Uint8Array([0x7b, 0xff, 0x7d]))).toThrow(/UTF-8 JSON/);
  });
});

describe("imageDigest", () => {
  it("extracts the digest", () => {
    expect(imageDigest(`ghcr.io/weftsh/x@${D1}`)).toBe(D1);
    expect(imageDigest(`111122223333.dkr.ecr.us-east-1.amazonaws.com/mirror/x:1.2.3@${D1}`)).toBe(D1);
  });

  it("requires a digest", () => {
    expect(() => imageDigest("ghcr.io/weftsh/x:1.2.3")).toThrow(/not pinned by digest/);
    expect(() => imageDigest("ghcr.io/weftsh/x@sha256:abc")).toThrow(/not pinned by digest/);
    expect(() => imageDigest(`@${D1}`)).toThrow(/not pinned by digest/);
  });
});

describe("checkRelease", () => {
  const manifest = parseManifest(bytes(sampleManifest()));
  const good = {
    version: "1.2.3",
    images: { "control-plane": `ghcr.io/weftsh/sandbox-control-plane@${D1}`, "egress-gateway": `mirror.example.com/gw@${D2}` },
    functionCode: { "functions/egress-ca.zip": ZIP_B64 },
  };

  it("accepts matching images (from any repository) and function code", () => {
    expect(checkRelease(manifest, good)).toEqual([]);
  });

  it("reports a version mismatch", () => {
    expect(checkRelease(manifest, { ...good, version: "1.2.4" })).toEqual([
      "the signed manifest is for version 1.2.3, but the template is version 1.2.4",
    ]);
  });

  it("reports unsigned or swapped image digests", () => {
    const problems = checkRelease(manifest, {
      ...good,
      images: { "control-plane": `x@${D2}`, "egress-gateway": "x:latest" },
    });
    expect(problems).toHaveLength(2);
    expect(problems[0]).toMatch(/control-plane image digest .* is not the signed release digest/);
    expect(problems[1]).toMatch(/not pinned by digest/);
  });

  it("reports an image component the manifest does not list", () => {
    expect(checkRelease(manifest, { ...good, images: { other: `x@${D1}` } })).toEqual(["the signed manifest lists no other image"]);
  });

  it("reports Lambda code that differs from the release", () => {
    const tampered = Buffer.from("d".repeat(64), "hex").toString("base64");
    const problems = checkRelease(manifest, { ...good, functionCode: { "functions/egress-ca.zip": tampered, "functions/x.zip": ZIP_B64 } });
    expect(problems[0]).toMatch(/deployed Lambda code for functions\/egress-ca.zip has SHA-256 d{64}/);
    expect(problems[1]).toBe("the signed manifest lists no functions/x.zip");
  });

  it("converts Lambda's base64 CodeSha256 to hex", () => {
    expect(base64ToHex(ZIP_B64)).toBe(ZIP_HEX);
  });
});

describe("checkAmi", () => {
  const manifest: ReleaseManifest = parseManifest(bytes(sampleManifest()));
  const ami = { imageId: "ami-0123456789abcdef0", state: "available", architecture: "x86_64" };

  it("accepts the signed AMI for the region", () => {
    expect(checkAmi(manifest, "us-east-1", ami, ami.imageId)).toEqual([]);
  });

  it("rejects any other AMI, including the signed AMI of another region", () => {
    expect(checkAmi(manifest, "us-east-1", { ...ami, imageId: "ami-0fedcba9876543210" }, "ami-0fedcba9876543210")[0]).toMatch(
      /is not the signed release AMI for us-east-1/,
    );
  });

  it("rejects regions the release does not cover", () => {
    expect(checkAmi(manifest, "ap-south-2", ami, ami.imageId)[0]).toMatch(/has no host AMI for ap-south-2/);
  });

  it("explains an AMI that is not shared with the account", () => {
    expect(checkAmi(manifest, "us-east-1", undefined, ami.imageId)[0]).toMatch(/not available to this account.*license/);
  });

  it("rejects unavailable or non-x86_64 images", () => {
    expect(checkAmi(manifest, "us-east-1", { ...ami, state: "deregistered", architecture: "arm64" }, ami.imageId)).toHaveLength(2);
  });
});
