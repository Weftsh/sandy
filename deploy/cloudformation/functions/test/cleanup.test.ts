import type { CloudFormationCustomResourceEvent } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";

import { handleCleanup, type CleanupDeps, type ObjectVersion } from "../src/cleanup/handler.js";

function event(requestType: "Create" | "Update" | "Delete", props: Record<string, unknown>): CloudFormationCustomResourceEvent {
  const base = {
    ServiceToken: "x",
    ResponseURL: "https://example.com/r",
    StackId: "arn:aws:cloudformation:us-east-1:111122223333:stack/weft/1",
    RequestId: "r",
    LogicalResourceId: "Cleanup",
    ResourceType: "Custom::WeftCleanup",
    ResourceProperties: { ServiceToken: "x", ...props },
  };
  if (requestType === "Create") return { ...base, RequestType: "Create" };
  if (requestType === "Update") return { ...base, RequestType: "Update", PhysicalResourceId: "weft-cleanup", OldResourceProperties: { ServiceToken: "x" } };
  return { ...base, RequestType: "Delete", PhysicalResourceId: "weft-cleanup" };
}

/** An in-memory versioned bucket store. */
function fakeS3(initial: Record<string, number>, opts: { remainingMs?: () => number; failKey?: string } = {}) {
  const buckets = new Map<string, ObjectVersion[]>();
  for (const [b, n] of Object.entries(initial)) {
    buckets.set(
      b,
      Array.from({ length: n }, (_, i) => ({ key: `snapshots/${i}`, versionId: `v${i}` })),
    );
  }
  const log: string[] = [];
  const deps: CleanupDeps = {
    bucketExists: vi.fn(async (b: string) => buckets.has(b)),
    expireEverything: vi.fn(async (b: string) => void log.push(`lifecycle ${b}`)),
    listVersions: vi.fn(async (b: string, keyMarker?: string) => {
      const all = buckets.get(b) ?? [];
      const start = keyMarker ? all.findIndex((v) => v.key === keyMarker) + 1 : 0;
      const page = all.slice(start, start + 1000);
      const more = start + 1000 < all.length;
      return more ? { versions: page, nextKeyMarker: page.at(-1)!.key, nextVersionIdMarker: page.at(-1)!.versionId } : { versions: page };
    }),
    deleteVersions: vi.fn(async (_b: string, versions: ObjectVersion[]) => {
      log.push(`delete ${versions.length}`);
      return versions.filter((v) => v.key === opts.failKey).map((v) => `${v.key}: AccessDenied`);
    }),
    abortMultipartUploads: vi.fn(async (b: string) => void log.push(`abort ${b}`)),
    deleteBucket: vi.fn(async (b: string) => {
      buckets.delete(b);
      log.push(`deleteBucket ${b}`);
    }),
    scheduleKeyDeletion: vi.fn(async (k: string, d: number) => void log.push(`scheduleKeyDeletion ${k} ${d}`)),
    remainingMs: opts.remainingMs ?? (() => 600_000),
  };
  return { deps, buckets, log };
}

const props = { BucketNames: ["artifacts"], Retain: "false", KmsKeyId: "key-1", PendingWindowInDays: "7" };

describe("Custom::WeftCleanup", () => {
  it("does nothing on create and update", async () => {
    const { deps, log } = fakeS3({ artifacts: 3 });
    expect((await handleCleanup(event("Create", props), deps)).physicalResourceId).toBe("weft-cleanup");
    await handleCleanup(event("Update", props), deps);
    expect(log).toEqual([]);
  });

  it("empties every version page, deletes the bucket, then schedules the key for deletion", async () => {
    const { deps, buckets, log } = fakeS3({ artifacts: 2500 });
    await handleCleanup(event("Delete", props), deps);
    expect(buckets.size).toBe(0);
    expect(log).toEqual([
      "lifecycle artifacts",
      "abort artifacts",
      "delete 1000",
      "delete 1000",
      "delete 500",
      "abort artifacts",
      "deleteBucket artifacts",
      "scheduleKeyDeletion key-1 7",
    ]);
  });

  it("retains buckets and key when asked", async () => {
    const { deps, buckets, log } = fakeS3({ artifacts: 5 });
    await handleCleanup(event("Delete", { ...props, Retain: "true" }), deps);
    expect(buckets.get("artifacts")).toHaveLength(5);
    expect(log).toEqual([]);
  });

  it("skips buckets that are already gone", async () => {
    const { deps, log } = fakeS3({});
    await handleCleanup(event("Delete", props), deps);
    expect(log).toEqual(["scheduleKeyDeletion key-1 7"]);
  });

  it("leaves the bucket (with an expire-everything rule) and the key when it runs out of time", async () => {
    let calls = 0;
    const { deps, buckets, log } = fakeS3({ artifacts: 5000 }, { remainingMs: () => (calls++ < 2 ? 600_000 : 30_000) });
    const res = await handleCleanup(event("Delete", props), deps);
    expect(res.physicalResourceId).toBe("weft-cleanup");
    expect(buckets.has("artifacts")).toBe(true);
    expect(log[0]).toBe("lifecycle artifacts");
    expect(log.some((l) => l.startsWith("scheduleKeyDeletion"))).toBe(false);
  });

  it("fails loudly when objects cannot be deleted", async () => {
    const { deps } = fakeS3({ artifacts: 3 }, { failKey: "snapshots/1" });
    await expect(handleCleanup(event("Delete", props), deps)).rejects.toThrow(/could not delete 1 objects from artifacts/);
    expect(deps.scheduleKeyDeletion).not.toHaveBeenCalled();
  });
});
