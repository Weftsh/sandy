#!/usr/bin/env node
// Bundles each function into a single CommonJS file and packs it into a
// byte-for-byte reproducible zip: dist/<name>.zip, with index.js (handler
// "index.handler") plus any extra files the function needs.
//
// verify-release requires src/verify-release/trusted-root.json, which the
// release workflow fetches from Sigstore's TUF repository first
// (`pnpm run fetch-trusted-root`).
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");

const functions = {
  "verify-release": { extra: { "trusted-root.json": "src/verify-release/trusted-root.json" } },
  "egress-ca": { extra: {} },
  cleanup: { extra: {} },
};

// --- minimal deterministic zip writer (DEFLATE, fixed timestamps) ----------
const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
// 1980-01-01 00:00:00, the earliest DOS timestamp.
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;

function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of [...entries].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const nameBuf = Buffer.from(name, "utf8");
    const compressed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBuf, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix, 2.0
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(((0o100644 << 16) >>> 0), 38); // -rw-r--r--
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + compressed.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.size, 8);
  end.writeUInt16LE(entries.size, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}

// --- build -------------------------------------------------------------------
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
const hashes = {};
for (const [name, { extra }] of Object.entries(functions)) {
  const result = await build({
    entryPoints: [join(root, "src", name, "index.ts")],
    bundle: true,
    platform: "node",
    target: "node22",
    format: "cjs",
    minify: false,
    sourcemap: false,
    legalComments: "inline",
    write: false,
    logLevel: "warning",
    // Reproducible output regardless of the checkout path.
    absWorkingDir: root,
  });
  const entries = new Map([["index.js", Buffer.from(result.outputFiles[0].contents)]]);
  for (const [zipName, src] of Object.entries(extra)) {
    const path = join(root, src);
    if (!existsSync(path)) {
      throw new Error(`${src} is missing; run \`pnpm run fetch-trusted-root\` first`);
    }
    entries.set(zipName, readFileSync(path));
  }
  const archive = zip(entries);
  const out = join(dist, `${name}.zip`);
  writeFileSync(out, archive);
  hashes[`functions/${name}.zip`] = createHash("sha256").update(archive).digest("hex");
  console.log(`${out} ${archive.length} bytes sha256=${hashes[`functions/${name}.zip`]}`);
}
writeFileSync(join(dist, "SHA256SUMS.json"), JSON.stringify(hashes, null, 2) + "\n");
