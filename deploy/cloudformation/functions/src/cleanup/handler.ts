/**
 * `Custom::WeftCleanup`: makes stack deletion clean.
 *
 * The stack's buckets and its KMS key carry `DeletionPolicy:
 * RetainExceptOnCreate`, so CloudFormation itself never deletes data. When
 * the stack is deleted and the customer did not choose to retain the
 * buckets, this resource (deleted after every service that writes to them)
 * empties and deletes the buckets (all versions, delete markers and
 * unfinished multipart uploads) and then schedules the KMS key for deletion.
 * With `Retain` set it does nothing, and buckets and key stay.
 *
 * If a bucket holds more objects than can be deleted before the Lambda
 * timeout, it installs a lifecycle rule that expires everything, reports
 * success so the rest of the stack can go, and leaves the (soon empty) bucket
 * and the key for the operator.
 */
import type { Event, ResourceResult } from "../shared/custom-resource.js";
import { stringList } from "../shared/custom-resource.js";

export interface ObjectVersion {
  key: string;
  versionId?: string;
}

export interface VersionPage {
  versions: ObjectVersion[];
  nextKeyMarker?: string;
  nextVersionIdMarker?: string;
}

export interface CleanupDeps {
  /** Returns false if the bucket does not exist. */
  bucketExists(bucket: string): Promise<boolean>;
  expireEverything(bucket: string): Promise<void>;
  listVersions(bucket: string, keyMarker?: string, versionIdMarker?: string): Promise<VersionPage>;
  /** Deletes up to 1000 versions; returns the keys that failed. */
  deleteVersions(bucket: string, versions: ObjectVersion[]): Promise<string[]>;
  abortMultipartUploads(bucket: string): Promise<void>;
  deleteBucket(bucket: string): Promise<void>;
  scheduleKeyDeletion(keyId: string, pendingWindowInDays: number): Promise<void>;
  /** Milliseconds left before the handler must give up. */
  remainingMs(): number;
}

/** Stop starting new work with this much time left. */
const STOP_MARGIN_MS = 60_000;

/** Empties and deletes one bucket. Returns false if it ran out of time. */
export async function emptyAndDeleteBucket(bucket: string, deps: CleanupDeps): Promise<boolean> {
  if (!(await deps.bucketExists(bucket))) return true;
  // Fallback first: if this run cannot finish, S3 finishes emptying the bucket.
  await deps.expireEverything(bucket);
  await deps.abortMultipartUploads(bucket);

  let keyMarker: string | undefined;
  let versionIdMarker: string | undefined;
  let deleted = 0;
  for (;;) {
    if (deps.remainingMs() < STOP_MARGIN_MS) return false;
    const page = await deps.listVersions(bucket, keyMarker, versionIdMarker);
    if (page.versions.length > 0) {
      const failed = await deps.deleteVersions(bucket, page.versions);
      if (failed.length > 0) throw new Error(`could not delete ${failed.length} objects from ${bucket}, e.g. ${failed[0]}`);
      deleted += page.versions.length;
    }
    if (!page.nextKeyMarker && !page.nextVersionIdMarker) break;
    keyMarker = page.nextKeyMarker;
    versionIdMarker = page.nextVersionIdMarker;
  }
  // Uploads started while listing (there should be none: writers are gone).
  await deps.abortMultipartUploads(bucket);
  await deps.deleteBucket(bucket);
  console.log(JSON.stringify({ msg: "bucket deleted", bucket, objectVersionsDeleted: deleted }));
  return true;
}

export async function handleCleanup(event: Event, deps: CleanupDeps): Promise<ResourceResult> {
  const physicalResourceId = event.RequestType === "Create" ? "weft-cleanup" : event.PhysicalResourceId;
  if (event.RequestType !== "Delete") return { physicalResourceId };

  const props = event.ResourceProperties as Record<string, unknown>;
  if (props.Retain === "true") {
    console.log(JSON.stringify({ msg: "retaining buckets and KMS key as requested" }));
    return { physicalResourceId };
  }
  const buckets = stringList(props, "BucketNames");
  const keyId = typeof props.KmsKeyId === "string" ? props.KmsKeyId : "";
  const pendingDays = Number(props.PendingWindowInDays ?? "7");

  const leftBehind: string[] = [];
  for (const bucket of buckets) {
    if (!(await emptyAndDeleteBucket(bucket, deps))) leftBehind.push(bucket);
  }
  if (leftBehind.length > 0) {
    // Objects left in the bucket are still encrypted with the key.
    console.warn(
      JSON.stringify({
        msg: "buckets not fully emptied before the timeout; a lifecycle rule will expire the remaining objects. " +
          "Delete the buckets and schedule deletion of the KMS key when they are empty.",
        buckets: leftBehind,
        keyId,
      }),
    );
    return { physicalResourceId };
  }
  if (keyId) {
    await deps.scheduleKeyDeletion(keyId, pendingDays);
    console.log(JSON.stringify({ msg: "KMS key scheduled for deletion", keyId, pendingDays }));
  }
  return { physicalResourceId };
}
