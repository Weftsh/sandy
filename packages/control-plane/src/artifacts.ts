/**
 * Template and snapshot artifacts in S3.
 *
 * Hosts have no S3 permissions. For each upload the control plane starts a
 * multipart upload, hands the host presigned part URLs, and completes the
 * upload with the ETags the host reports. Downloads use presigned GETs.
 */
import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  S3Client,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

import type { ArtifactObject } from "./store/types.js";

export const PART_SIZE = 256 * 1024 * 1024;
/** 64 parts of 256 MiB: up to 16 GiB per compressed artifact. */
export const MAX_PARTS = 64;
const URL_TTL_SEC = 3 * 60 * 60;

export type ArtifactName = "rootfs" | "memory" | "vmstate";
const NAMES: ArtifactName[] = ["rootfs", "memory", "vmstate"];

export interface UploadTarget {
  kind: "multipart";
  partSize: number;
  partUrls: string[];
}

export interface UploadedArtifact {
  sha256: string;
  size: number;
  parts?: { partNumber: number; etag: string }[];
}

export interface PendingUpload {
  targets: Record<ArtifactName, UploadTarget>;
  complete(result: Record<ArtifactName, UploadedArtifact>): Promise<Record<ArtifactName, ArtifactObject>>;
  abort(): Promise<void>;
}

export interface ArtifactRefs {
  rootfs: { url: string; sha256: string; size: number };
  memory: { url: string; sha256: string; size: number };
  vmstate: { url: string; sha256: string; size: number };
}

/**
 * Where template and snapshot artifacts live: S3 ({@link ArtifactStore}), or
 * a local directory in development (`LocalArtifactStore` in dev-artifacts.ts).
 */
export interface Artifacts {
  /** Starts uploads of rootfs, memory and vmstate under `prefix`. */
  beginUpload(prefix: string): Promise<PendingUpload>;
  /** Download URLs a host can use without credentials. */
  presign(objects: Record<ArtifactName, ArtifactObject>): Promise<ArtifactRefs>;
  delete(objects: (ArtifactObject | undefined)[]): Promise<void>;
}

export class ArtifactStore implements Artifacts {
  constructor(
    private s3: S3Client,
    private bucket: string,
  ) {}

  /** Starts multipart uploads for rootfs, memory and vmstate under `prefix`. */
  async beginUpload(prefix: string): Promise<PendingUpload> {
    const started: { name: ArtifactName; key: string; uploadId: string }[] = [];
    try {
      for (const name of NAMES) {
        const key = `${prefix}/${name}.zst`;
        const out = await this.s3.send(new CreateMultipartUploadCommand({ Bucket: this.bucket, Key: key }));
        if (!out.UploadId) throw new Error("S3 returned no upload ID");
        started.push({ name, key, uploadId: out.UploadId });
      }
    } catch (e) {
      await Promise.allSettled(started.map((u) => this.s3.send(new AbortMultipartUploadCommand({ Bucket: this.bucket, Key: u.key, UploadId: u.uploadId }))));
      throw e;
    }
    const targets = {} as Record<ArtifactName, UploadTarget>;
    for (const u of started) {
      const partUrls: string[] = [];
      for (let n = 1; n <= MAX_PARTS; n++) {
        partUrls.push(
          await getSignedUrl(this.s3, new UploadPartCommand({ Bucket: this.bucket, Key: u.key, UploadId: u.uploadId, PartNumber: n }), {
            expiresIn: URL_TTL_SEC,
          }),
        );
      }
      targets[u.name] = { kind: "multipart", partSize: PART_SIZE, partUrls };
    }
    const abort = async () => {
      await Promise.allSettled(started.map((u) => this.s3.send(new AbortMultipartUploadCommand({ Bucket: this.bucket, Key: u.key, UploadId: u.uploadId }))));
    };
    return {
      targets,
      abort,
      complete: async (result) => {
        const out = {} as Record<ArtifactName, ArtifactObject>;
        try {
          for (const u of started) {
            const r = result[u.name];
            if (!r?.parts?.length) throw new Error(`host reported no parts for ${u.name}`);
            await this.s3.send(
              new CompleteMultipartUploadCommand({
                Bucket: this.bucket,
                Key: u.key,
                UploadId: u.uploadId,
                MultipartUpload: { Parts: r.parts.map((p) => ({ PartNumber: p.partNumber, ETag: p.etag })) },
              }),
            );
            out[u.name] = { key: u.key, sha256: r.sha256, size: r.size };
          }
        } catch (e) {
          await abort();
          throw e;
        }
        return out;
      },
    };
  }

  async presign(objects: Record<ArtifactName, ArtifactObject>): Promise<ArtifactRefs> {
    const ref = async (o: ArtifactObject) => ({
      url: await getSignedUrl(this.s3, new GetObjectCommand({ Bucket: this.bucket, Key: o.key }), { expiresIn: URL_TTL_SEC }),
      sha256: o.sha256,
      size: o.size,
    });
    return { rootfs: await ref(objects.rootfs), memory: await ref(objects.memory), vmstate: await ref(objects.vmstate) };
  }

  async delete(objects: (ArtifactObject | undefined)[]): Promise<void> {
    const keys = objects.filter((o): o is ArtifactObject => !!o).map((o) => ({ Key: o.key }));
    if (keys.length === 0) return;
    await this.s3.send(new DeleteObjectsCommand({ Bucket: this.bucket, Delete: { Objects: keys, Quiet: true } }));
  }
}
