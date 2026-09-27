/**
 * Sigstore (keyless) signature verification of the release manifest.
 *
 * The Sigstore trusted root (Fulcio CAs, Rekor and CT log keys, timestamp
 * authorities) is not fetched at install time: the release workflow fetches
 * it through Sigstore's TUF repository and bundles it next to this function
 * as `trusted-root.json`, so verification needs no network access beyond
 * reading the manifest itself.
 */
import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";

import type { SignerIdentity } from "./manifest.js";

export interface SignatureVerifier {
  /** Throws unless `bundle` is a valid Sigstore signature over `payload` by `identity`. */
  verify(bundle: unknown, payload: Buffer, identity: SignerIdentity): void;
}

export function sigstoreVerifier(trustedRootJson: unknown): SignatureVerifier {
  const trustMaterial = toTrustMaterial(TrustedRoot.fromJSON(trustedRootJson));
  // Same thresholds as `cosign verify-blob` and sigstore-js defaults: at least
  // one transparency log entry and one certificate transparency SCT.
  const verifier = new Verifier(trustMaterial, { tlogThreshold: 1, ctlogThreshold: 1 });
  return {
    verify(bundle, payload, identity) {
      let entity;
      try {
        entity = toSignedEntity(bundleFromJSON(bundle), payload);
      } catch (e) {
        throw new Error(`the release signature bundle is malformed: ${(e as Error).message}`);
      }
      try {
        verifier.verify(entity, {
          subjectAlternativeName: identity.subjectAlternativeName,
          extensions: { issuer: identity.issuer },
        });
      } catch (e) {
        throw new Error(`the release manifest signature did not verify: ${(e as Error).message}`);
      }
    },
  };
}
