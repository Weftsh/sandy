#!/usr/bin/env node
/**
 * weft-license: generate signing keys, issue and inspect license keys.
 *
 *   weft-license keygen --out <dir>
 *   weft-license issue --payload payload.json (--private-key key.pem | --kms-key-id <arn>)
 *   weft-license verify <license-key> --public-key <kid>=<pem-file> [--public-key ...]
 */
import { createPrivateKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { KMSClient } from "@aws-sdk/client-kms";

import { generateSigningKeyPair, issueLicenseKey, kmsSigner, localSigner } from "./issue.js";
import { trustedKeysFromPem, verifyLicenseKey, type LicensePayload } from "./key.js";
import { RELEASE_SIGNING_KEYS } from "./trusted-keys.js";

function usage(): never {
  process.stderr.write(
    [
      "usage:",
      "  weft-license keygen --out <dir>",
      "  weft-license issue --payload <payload.json> (--private-key <key.pem> | --kms-key-id <key-id>)",
      "  weft-license verify <license-key> [--public-key <kid>=<public.pem> ...]",
      "",
    ].join("\n"),
  );
  process.exit(2);
}

async function main(argv: string[]): Promise<void> {
  const [command, ...rest] = argv;
  switch (command) {
    case "keygen": {
      const { values } = parseArgs({ args: rest, options: { out: { type: "string" } } });
      if (!values.out) usage();
      mkdirSync(values.out, { recursive: true, mode: 0o700 });
      const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
      writeFileSync(join(values.out, "license-signing.pub.pem"), publicKeyPem);
      writeFileSync(join(values.out, "license-signing.key.pem"), privateKeyPem, { mode: 0o600 });
      process.stdout.write(`wrote ${values.out}/license-signing.{pub,key}.pem\n`);
      return;
    }
    case "issue": {
      const { values } = parseArgs({
        args: rest,
        options: {
          payload: { type: "string" },
          "private-key": { type: "string" },
          "kms-key-id": { type: "string" },
        },
      });
      if (!values.payload || (!values["private-key"] === !values["kms-key-id"])) usage();
      const payload = JSON.parse(readFileSync(values.payload, "utf8")) as LicensePayload;
      const signer = values["private-key"]
        ? localSigner(createPrivateKey(readFileSync(values["private-key"])))
        : kmsSigner(new KMSClient({}), values["kms-key-id"]!);
      process.stdout.write(`${await issueLicenseKey(payload, signer)}\n`);
      return;
    }
    case "verify": {
      const { values, positionals } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: { "public-key": { type: "string", multiple: true } },
      });
      const key = positionals[0];
      if (!key) usage();
      const pems: Record<string, string> = { ...RELEASE_SIGNING_KEYS };
      for (const entry of values["public-key"] ?? []) {
        const eq = entry.indexOf("=");
        if (eq <= 0) usage();
        pems[entry.slice(0, eq)] = readFileSync(entry.slice(eq + 1), "utf8");
      }
      const result = verifyLicenseKey(key, trustedKeysFromPem(pems));
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = result.ok ? 0 : 1;
      return;
    }
    default:
      usage();
  }
}

main(process.argv.slice(2)).catch((err: unknown) => {
  process.stderr.write(`weft-license: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
