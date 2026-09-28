import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { loadConfig } from "../src/config.js";
import { LocalArtifactStore } from "../src/dev-artifacts.js";

// Real HTTP, as the host agent uses: part uploads carry no content type.
let dir: string;
let api: FastifyInstance;
let store: LocalArtifactStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "weft-dev-artifacts-"));
  api = Fastify();
  await api.listen({ host: "127.0.0.1", port: 0 });
  const port = (api.server.address() as { port: number }).port;
  await api.close();
  api = Fastify();
  store = new LocalArtifactStore(dir, `http://127.0.0.1:${port}`);
  store.routes(api);
  await api.listen({ host: "127.0.0.1", port });
});

afterEach(async () => {
  await api.close();
  await rm(dir, { recursive: true, force: true });
});

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

async function put(url: string, body: Buffer, contentType?: string): Promise<Response> {
  return fetch(url, { method: "PUT", body, headers: contentType ? { "content-type": contentType } : {} });
}

/** Uploads `chunks` as consecutive parts and returns what a host reports. */
async function uploadParts(urls: string[], chunks: Buffer[]) {
  const parts = [];
  for (const [i, chunk] of chunks.entries()) {
    const res = await put(urls[i]!, chunk, i % 2 ? "application/octet-stream" : undefined);
    expect(res.status).toBe(200);
    parts.push({ partNumber: i + 1, etag: res.headers.get("etag")! });
  }
  const all = Buffer.concat(chunks);
  return { sha256: sha(all), size: all.length, parts };
}

describe("development artifact store", () => {
  it("round-trips multipart uploads through presigned URLs", async () => {
    const upload = await store.beginUpload("templates/tpl1/build1");
    const data = {
      rootfs: [Buffer.from("root-"), Buffer.alloc(70_000, 7)],
      memory: [Buffer.alloc(3 * 1024 * 1024, 1)],
      vmstate: [Buffer.from("state")],
    };
    const reported = {
      rootfs: await uploadParts(upload.targets.rootfs.partUrls, data.rootfs),
      memory: await uploadParts(upload.targets.memory.partUrls, data.memory),
      vmstate: await uploadParts(upload.targets.vmstate.partUrls, data.vmstate),
    };
    const objects = await upload.complete(reported);
    expect(objects.rootfs.key).toBe("templates/tpl1/build1/rootfs.zst");

    const refs = await store.presign(objects);
    for (const name of ["rootfs", "memory", "vmstate"] as const) {
      const res = await fetch(refs[name].url);
      expect(res.status).toBe(200);
      expect(Buffer.from(await res.arrayBuffer()).equals(Buffer.concat(data[name]))).toBe(true);
      expect(refs[name].sha256).toBe(reported[name].sha256);
    }

    await store.delete([objects.rootfs]);
    expect((await fetch(refs.rootfs.url)).status).toBe(404);
  });

  it("accepts only the exact URL it signed", async () => {
    const upload = await store.beginUpload("snapshots/sbx1/1");
    const [first, second] = upload.targets.memory.partUrls as [string, string];
    // Part 1's signature does not cover part 2.
    const forged = second.split("?")[0] + "?" + first.split("?")[1];
    expect((await put(forged, Buffer.from("x"))).status).toBe(403);
    const tampered = first.replace(/sig=[^&]+/, "sig=AAAA");
    expect((await put(tampered, Buffer.from("x"))).status).toBe(403);
    expect((await put(first.split("?")[0]!, Buffer.from("x"))).status).toBe(403);
    await upload.abort();
    // Aborted uploads are gone.
    expect((await put(first, Buffer.from("x"))).status).toBe(404);
  });

  it("refuses to complete with a wrong ETag or hash", async () => {
    const upload = await store.beginUpload("templates/tpl2/build2");
    const good = {
      rootfs: await uploadParts(upload.targets.rootfs.partUrls, [Buffer.from("a")]),
      memory: await uploadParts(upload.targets.memory.partUrls, [Buffer.from("b")]),
      vmstate: await uploadParts(upload.targets.vmstate.partUrls, [Buffer.from("c")]),
    };
    await expect(upload.complete({ ...good, memory: { ...good.memory, parts: [{ partNumber: 1, etag: '"nope"' }] } })).rejects.toThrow(/ETag/);

    const again = await store.beginUpload("templates/tpl2/build3");
    const reported = {
      rootfs: await uploadParts(again.targets.rootfs.partUrls, [Buffer.from("a")]),
      memory: await uploadParts(again.targets.memory.partUrls, [Buffer.from("b")]),
      vmstate: await uploadParts(again.targets.vmstate.partUrls, [Buffer.from("c")]),
    };
    await expect(again.complete({ ...reported, vmstate: { ...reported.vmstate, sha256: sha(Buffer.from("other")) } })).rejects.toThrow(/sha256/);
  });

  it("is only available in development mode", () => {
    vi.stubEnv("WEFT_DEV_MODE", "");
    vi.stubEnv("WEFT_DEV_ARTIFACTS_DIR", dir);
    expect(() => loadConfig()).toThrow(/WEFT_DEV_ARTIFACTS_DIR requires WEFT_DEV_MODE=1/);
    vi.unstubAllEnvs();
  });
});
