/**
 * Development stand-in for the S3 artifact bucket, served by the control
 * plane from a local directory with the same presigned-URL protocol.
 *
 * Firecracker hosts never talk to S3: they upload template and pause
 * snapshots in parts to URLs they are handed, report each part's ETag, and
 * download from presigned GETs. This store hands out URLs to the API server
 * instead, signed with a key that exists only in this process, so the host
 * agent's transfer code runs unchanged on one machine without AWS. It is
 * enabled only in development mode (WEFT_DEV_MODE=1 and
 * WEFT_DEV_ARTIFACTS_DIR); production uses the S3 ArtifactStore.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";

import type { FastifyInstance } from "fastify";

import { MAX_PARTS, PART_SIZE, type ArtifactName, type ArtifactRefs, type Artifacts, type PendingUpload, type UploadTarget } from "./artifacts.js";
import type { ArtifactObject } from "./store/types.js";

export const DEV_ARTIFACTS_ROUTE = "/dev/artifacts";
const URL_TTL_MS = 3 * 60 * 60 * 1000;
const NAMES: ArtifactName[] = ["rootfs", "memory", "vmstate"];
/** Keys are built by the control plane from its own IDs. */
const KEY = /^[A-Za-z0-9_-]+(\/[A-Za-z0-9_.-]+)*$/;

interface Upload {
  key: string;
  etags: Map<number, string>;
}

export class LocalArtifactStore implements Artifacts {
  private readonly secret = randomBytes(32);
  private readonly uploads = new Map<string, Upload>();

  /** `baseUrl` is how hosts reach the API server, e.g. http://127.0.0.1:3000. */
  constructor(
    private readonly dir: string,
    private readonly baseUrl: string,
  ) {}

  async beginUpload(prefix: string): Promise<PendingUpload> {
    const started: { name: ArtifactName; id: string }[] = [];
    const targets = {} as Record<ArtifactName, UploadTarget>;
    for (const name of NAMES) {
      const key = `${prefix}/${name}.zst`;
      if (!KEY.test(key) || key.includes("..")) throw new Error(`invalid artifact key ${key}`);
      const id = randomBytes(16).toString("hex");
      await mkdir(join(this.dir, "uploads", id), { recursive: true });
      this.uploads.set(id, { key, etags: new Map() });
      started.push({ name, id });
      const partUrls: string[] = [];
      for (let n = 1; n <= MAX_PARTS; n++) partUrls.push(this.url("PUT", `${DEV_ARTIFACTS_ROUTE}/uploads/${id}/${n}`));
      targets[name] = { kind: "multipart", partSize: PART_SIZE, partUrls };
    }
    const abort = async () => {
      for (const u of started) {
        this.uploads.delete(u.id);
        await rm(join(this.dir, "uploads", u.id), { recursive: true, force: true });
      }
    };
    return {
      targets,
      abort,
      complete: async (result) => {
        const out = {} as Record<ArtifactName, ArtifactObject>;
        try {
          for (const u of started) {
            out[u.name] = await this.assemble(u.id, result[u.name]);
          }
        } finally {
          await abort();
        }
        return out;
      },
    };
  }

  async presign(objects: Record<ArtifactName, ArtifactObject>): Promise<ArtifactRefs> {
    const ref = (o: ArtifactObject) => ({ url: this.url("GET", `${DEV_ARTIFACTS_ROUTE}/objects/${o.key}`), sha256: o.sha256, size: o.size });
    return { rootfs: ref(objects.rootfs), memory: ref(objects.memory), vmstate: ref(objects.vmstate) };
  }

  async delete(objects: (ArtifactObject | undefined)[]): Promise<void> {
    for (const o of objects) {
      if (o && KEY.test(o.key) && !o.key.includes("..")) await rm(this.objectPath(o.key), { force: true });
    }
  }

  /** Adds the upload and download routes to the API server. */
  routes(api: FastifyInstance): void {
    void api.register(async (scope) => {
      // Parts are raw bytes with any content type, or none; they are
      // streamed to disk, not parsed.
      scope.removeAllContentTypeParsers();
      scope.addContentTypeParser("*", (_req, _payload, done) => done(null));

      scope.put(`${DEV_ARTIFACTS_ROUTE}/uploads/:id/:part`, async (req, reply) => {
        const { id, part } = req.params as { id: string; part: string };
        if (!this.verified("PUT", `${DEV_ARTIFACTS_ROUTE}/uploads/${id}/${part}`, req.query)) return reply.code(403).send();
        const upload = this.uploads.get(id);
        const n = Number(part);
        if (!upload || !Number.isInteger(n) || n < 1 || n > MAX_PARTS) return reply.code(404).send();
        const hash = createHash("sha256");
        let size = 0;
        await pipeline(
          req.raw,
          async function* (source: AsyncIterable<Buffer>) {
            for await (const chunk of source) {
              size += chunk.length;
              if (size > PART_SIZE) throw new Error(`part exceeds ${PART_SIZE} bytes`);
              hash.update(chunk);
              yield chunk;
            }
          },
          createWriteStream(join(this.dir, "uploads", id, String(n))),
        );
        const etag = `"${hash.digest("hex")}"`;
        upload.etags.set(n, etag);
        return reply.header("etag", etag).code(200).send();
      });

      scope.get(`${DEV_ARTIFACTS_ROUTE}/objects/*`, async (req, reply) => {
        const key = (req.params as { "*": string })["*"];
        if (!KEY.test(key) || key.includes("..") || !this.verified("GET", `${DEV_ARTIFACTS_ROUTE}/objects/${key}`, req.query)) {
          return reply.code(403).send();
        }
        const st = await stat(this.objectPath(key)).catch(() => undefined);
        if (!st?.isFile()) return reply.code(404).send();
        return reply.header("content-length", st.size).type("application/octet-stream").send(createReadStream(this.objectPath(key)));
      });
    });
  }

  /** Joins the parts a host reported, checking their ETags, size and hash. */
  private async assemble(id: string, reported: { sha256: string; size: number; parts?: { partNumber: number; etag: string }[] } | undefined): Promise<ArtifactObject> {
    const upload = this.uploads.get(id);
    if (!upload) throw new Error("unknown upload");
    const parts = [...(reported?.parts ?? [])].sort((a, b) => a.partNumber - b.partNumber);
    if (!reported || parts.length === 0) throw new Error(`host reported no parts for ${upload.key}`);
    parts.forEach((p, i) => {
      if (p.partNumber !== i + 1) throw new Error(`${upload.key}: parts are not numbered 1..${parts.length}`);
      if (upload.etags.get(p.partNumber) !== p.etag) throw new Error(`${upload.key}: part ${p.partNumber} ETag does not match`);
    });
    const target = this.objectPath(upload.key);
    await mkdir(dirname(target), { recursive: true });
    const tmp = `${target}.${id}.tmp`;
    const hash = createHash("sha256");
    let size = 0;
    const out = createWriteStream(tmp);
    try {
      for (const p of parts) {
        for await (const chunk of createReadStream(join(this.dir, "uploads", id, String(p.partNumber)))) {
          hash.update(chunk as Buffer);
          size += (chunk as Buffer).length;
          if (!out.write(chunk)) await new Promise<void>((r) => out.once("drain", () => r()));
        }
      }
      await new Promise<void>((resolve, reject) => out.end((e?: Error | null) => (e ? reject(e) : resolve())));
      const sha256 = hash.digest("hex");
      if (size !== reported.size || sha256 !== reported.sha256) {
        throw new Error(`${upload.key}: stored ${size} bytes (sha256 ${sha256}), host reported ${reported.size} (${reported.sha256})`);
      }
      await rename(tmp, target);
    } catch (e) {
      out.destroy();
      await rm(tmp, { force: true });
      throw e;
    }
    return { key: upload.key, sha256: reported.sha256, size: reported.size };
  }

  private objectPath(key: string): string {
    return join(this.dir, "objects", key);
  }

  private url(method: "GET" | "PUT", path: string): string {
    const exp = String(Date.now() + URL_TTL_MS);
    return `${this.baseUrl}${path}?exp=${exp}&sig=${this.sign(method, path, exp)}`;
  }

  private sign(method: string, path: string, exp: string): string {
    return createHmac("sha256", this.secret).update(`${method} ${path} ${exp}`).digest("base64url");
  }

  private verified(method: string, path: string, query: unknown): boolean {
    const { exp, sig } = (query ?? {}) as { exp?: string; sig?: string };
    if (typeof exp !== "string" || typeof sig !== "string" || !(Number(exp) > Date.now())) return false;
    const want = Buffer.from(this.sign(method, path, exp));
    const got = Buffer.from(sig);
    return want.length === got.length && timingSafeEqual(want, got);
  }
}
