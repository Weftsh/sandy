/**
 * Exercises the production Sigstore verifier against real, public Sigstore
 * material (no network):
 *
 * - fixtures/sigstore/cosign_checksums.txt(.sigstore.json): the release
 *   checksums of sigstore/cosign v3.1.3 and their keyless bundle (signer
 *   keyless@projectsigstore.iam.gserviceaccount.com, issuer
 *   https://accounts.google.com), from the cosign GitHub release.
 * - fixtures/sigstore/trusted-root.json: the Sigstore public-good trusted
 *   root, fetched through TUF with @sigstore/tuf exactly as
 *   scripts/fetch-trusted-root.mjs does in the release workflow.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { sigstoreVerifier } from "../src/verify-release/signature.js";

const dir = join(import.meta.dirname, "fixtures", "sigstore");
const trustedRoot = JSON.parse(readFileSync(join(dir, "trusted-root.json"), "utf8"));
const bundle = JSON.parse(readFileSync(join(dir, "cosign_checksums.txt.sigstore.json"), "utf8"));
const payload = readFileSync(join(dir, "cosign_checksums.txt"));
const identity = { subjectAlternativeName: "keyless@projectsigstore.iam.gserviceaccount.com", issuer: "https://accounts.google.com" };

describe("sigstoreVerifier", () => {
  const verifier = sigstoreVerifier(trustedRoot);

  it("accepts a genuine keyless signature from the expected identity", () => {
    expect(() => verifier.verify(bundle, payload, identity)).not.toThrow();
  });

  it("rejects a modified payload", () => {
    const tampered = Buffer.concat([payload, Buffer.from("\n")]);
    expect(() => verifier.verify(bundle, tampered, identity)).toThrow(/signature did not verify/);
  });

  it("rejects the right signature from the wrong identity", () => {
    const releaseWorkflow = {
      subjectAlternativeName: "https://github.com/weftsh/byoc/.github/workflows/release.yml@refs/tags/v1.2.3",
      issuer: "https://token.actions.githubusercontent.com",
    };
    expect(() => verifier.verify(bundle, payload, releaseWorkflow)).toThrow(/signature did not verify.*identity/);
    expect(() => verifier.verify(bundle, payload, { ...identity, issuer: "https://token.actions.githubusercontent.com" })).toThrow(
      /signature did not verify/,
    );
  });

  it("rejects a bundle whose certificate is not from the trusted Fulcio", () => {
    const untrusted = { ...trustedRoot, certificateAuthorities: [] };
    expect(() => sigstoreVerifier(untrusted).verify(bundle, payload, identity)).toThrow(/signature did not verify/);
  });

  it("rejects malformed bundles", () => {
    expect(() => verifier.verify({ mediaType: "nope" }, payload, identity)).toThrow(/malformed/);
    const noTlog = structuredClone(bundle);
    noTlog.verificationMaterial.tlogEntries = [];
    expect(() => verifier.verify(noTlog, payload, identity)).toThrow();
  });
});
