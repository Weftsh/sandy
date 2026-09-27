/** Lambda entry point for `Custom::WeftCleanup`. */
import type { Context } from "aws-lambda";
import { KMSClient, ScheduleKeyDeletionCommand } from "@aws-sdk/client-kms";
import {
  AbortMultipartUploadCommand,
  DeleteBucketCommand,
  DeleteObjectsCommand,
  HeadBucketCommand,
  ListMultipartUploadsCommand,
  ListObjectVersionsCommand,
  PutBucketLifecycleConfigurationCommand,
  S3Client,
} from "@aws-sdk/client-s3";

import { customResource } from "../shared/custom-resource.js";
import { handleCleanup, type CleanupDeps } from "./handler.js";

const region = process.env.AWS_REGION ?? "us-east-1";
const s3 = new S3Client({ region });
const kms = new KMSClient({ region });

function depsFor(context: Context): CleanupDeps {
  return {
    async bucketExists(bucket) {
      try {
        await s3.send(new HeadBucketCommand({ Bucket: bucket }));
        return true;
      } catch (e) {
        const status = (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
        if ((e as Error).name === "NotFound" || (e as Error).name === "NoSuchBucket" || status === 404) return false;
        throw e;
      }
    },
    async expireEverything(bucket) {
      await s3.send(
        new PutBucketLifecycleConfigurationCommand({
          Bucket: bucket,
          LifecycleConfiguration: {
            Rules: [
              {
                ID: "weft-uninstall-expire-everything",
                Status: "Enabled",
                Filter: { Prefix: "" },
                Expiration: { Days: 1 },
                NoncurrentVersionExpiration: { NoncurrentDays: 1 },
                AbortIncompleteMultipartUpload: { DaysAfterInitiation: 1 },
              },
              {
                ID: "weft-uninstall-remove-delete-markers",
                Status: "Enabled",
                Filter: { Prefix: "" },
                Expiration: { ExpiredObjectDeleteMarker: true },
              },
            ],
          },
        }),
      );
    },
    async listVersions(bucket, keyMarker, versionIdMarker) {
      const res = await s3.send(
        new ListObjectVersionsCommand({ Bucket: bucket, KeyMarker: keyMarker, VersionIdMarker: versionIdMarker, MaxKeys: 1000 }),
      );
      const versions = [...(res.Versions ?? []), ...(res.DeleteMarkers ?? [])]
        .filter((v) => v.Key !== undefined)
        .map((v) => ({ key: v.Key!, versionId: v.VersionId }));
      return res.IsTruncated
        ? { versions, nextKeyMarker: res.NextKeyMarker, nextVersionIdMarker: res.NextVersionIdMarker }
        : { versions };
    },
    async deleteVersions(bucket, versions) {
      const res = await s3.send(
        new DeleteObjectsCommand({
          Bucket: bucket,
          Delete: { Quiet: true, Objects: versions.map((v) => ({ Key: v.key, VersionId: v.versionId })) },
        }),
      );
      return (res.Errors ?? []).map((e) => `${e.Key}: ${e.Code}`);
    },
    async abortMultipartUploads(bucket) {
      let keyMarker: string | undefined;
      let uploadIdMarker: string | undefined;
      for (;;) {
        const res = await s3.send(
          new ListMultipartUploadsCommand({ Bucket: bucket, KeyMarker: keyMarker, UploadIdMarker: uploadIdMarker }),
        );
        for (const u of res.Uploads ?? []) {
          await s3.send(new AbortMultipartUploadCommand({ Bucket: bucket, Key: u.Key, UploadId: u.UploadId }));
        }
        if (!res.IsTruncated) return;
        keyMarker = res.NextKeyMarker;
        uploadIdMarker = res.NextUploadIdMarker;
      }
    },
    async deleteBucket(bucket) {
      await s3.send(new DeleteBucketCommand({ Bucket: bucket }));
    },
    async scheduleKeyDeletion(keyId, pendingWindowInDays) {
      try {
        await kms.send(new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: pendingWindowInDays }));
      } catch (e) {
        // Already pending deletion (for example on a retried stack delete).
        if ((e as Error).name !== "KMSInvalidStateException") throw e;
      }
    },
    remainingMs: () => context.getRemainingTimeInMillis(),
  };
}

export const handler = customResource((event, context) => handleCleanup(event, depsFor(context)));
