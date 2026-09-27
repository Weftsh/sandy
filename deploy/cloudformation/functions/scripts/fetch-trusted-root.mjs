#!/usr/bin/env node
// Fetches Sigstore's trusted root (Fulcio CAs, Rekor/CT log keys, timestamp
// authorities) through the Sigstore TUF repository, verified from the TUF
// root embedded in @sigstore/tuf, and writes it where the verify-release
// bundle picks it up. Run by the release workflow right before bundling, so
// the root is current for the signature the same workflow is about to make.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { TrustedRoot } from "@sigstore/protobuf-specs";
import { getTrustedRoot } from "@sigstore/tuf";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "src", "verify-release", "trusted-root.json");
const cachePath = mkdtempSync(join(tmpdir(), "weft-tuf-"));
try {
  // A fresh cache forces a full TUF update from the embedded root.
  const trustedRoot = await getTrustedRoot({ cachePath, forceInit: true });
  if (trustedRoot.certificateAuthorities.length === 0 || trustedRoot.tlogs.length === 0) {
    throw new Error("the Sigstore trusted root has no certificate authorities or transparency logs");
  }
  writeFileSync(out, JSON.stringify(TrustedRoot.toJSON(trustedRoot), null, 2) + "\n");
  console.log(`wrote ${out}`);
} finally {
  rmSync(cachePath, { recursive: true, force: true });
}
