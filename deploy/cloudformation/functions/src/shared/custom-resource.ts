/**
 * Minimal CloudFormation custom resource runtime: runs a handler, then PUTs
 * the result to the presigned ResponseURL CloudFormation supplied.
 *
 * Every invocation answers exactly once, before the Lambda times out, so a
 * failure surfaces in the stack events instead of a one-hour hang.
 */
import type { CloudFormationCustomResourceEvent, Context } from "aws-lambda";

export type Event = CloudFormationCustomResourceEvent;

export interface ResourceResult {
  physicalResourceId: string;
  data?: Record<string, string>;
}

export type ResourceHandler = (event: Event, context: Context) => Promise<ResourceResult>;

/** PUTs the response body to CloudFormation. Injectable for tests. */
export type ResponseSender = (url: string, body: string) => Promise<void>;

/** CloudFormation rejects responses larger than 4096 bytes. */
const MAX_RESPONSE_BYTES = 4096;
/** Time kept in reserve to send the response after the handler gives up. */
const RESPONSE_RESERVE_MS = 10_000;

export const sendResponse: ResponseSender = async (url, body) => {
  // A Uint8Array body keeps fetch from adding a Content-Type header, which
  // the presigned URL does not sign.
  const bytes = new TextEncoder().encode(body);
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, { method: "PUT", body: bytes });
      if (res.ok) return;
      lastError = new Error(`CloudFormation response upload failed with HTTP ${res.status}`);
    } catch (e) {
      lastError = e;
    }
    await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
  }
  throw lastError;
};

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 3)}...`;
}

/** Rejects if `promise` does not settle within `ms`. */
async function withDeadline<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${Math.round(ms / 1000)} s`)), Math.max(ms, 1000));
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

export function buildResponse(
  event: Event,
  context: Pick<Context, "logStreamName">,
  outcome: { ok: true; result: ResourceResult } | { ok: false; error: string },
): string {
  const physicalResourceId = outcome.ok
    ? outcome.result.physicalResourceId
    : event.RequestType === "Create"
      ? // CloudFormation sends a Delete for this ID when it rolls back.
        `failed-create-${event.RequestId}`
      : event.PhysicalResourceId;
  const base = {
    Status: outcome.ok ? "SUCCESS" : "FAILED",
    PhysicalResourceId: physicalResourceId,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
  };
  if (outcome.ok) {
    const body = JSON.stringify({ ...base, Data: outcome.result.data ?? {} });
    if (Buffer.byteLength(body) > MAX_RESPONSE_BYTES) {
      return buildResponse(event, context, { ok: false, error: "response data exceeds the 4096-byte limit" });
    }
    return body;
  }
  const reason = truncate(`${outcome.error} (log stream: ${context.logStreamName})`, 1500);
  return JSON.stringify({ ...base, Reason: reason });
}

/** Wraps a handler into a Lambda entry point that always answers CloudFormation. */
export function customResource(handler: ResourceHandler, send: ResponseSender = sendResponse) {
  return async (event: Event, context: Context): Promise<void> => {
    // Never log ResourceProperties wholesale: keep the log free of anything
    // a future property might carry.
    console.log(
      JSON.stringify({
        msg: "custom resource request",
        requestType: event.RequestType,
        resourceType: event.ResourceType,
        logicalResourceId: event.LogicalResourceId,
        stackId: event.StackId,
      }),
    );
    let body: string;
    try {
      const budget = context.getRemainingTimeInMillis() - RESPONSE_RESERVE_MS;
      const result = await withDeadline(handler(event, context), budget);
      body = buildResponse(event, context, { ok: true, result });
      console.log(JSON.stringify({ msg: "custom resource succeeded", physicalResourceId: result.physicalResourceId }));
    } catch (e) {
      const error = errorMessage(e);
      console.error(JSON.stringify({ msg: "custom resource failed", error }));
      body = buildResponse(event, context, { ok: false, error });
    }
    await send(event.ResponseURL, body);
  };
}

/** Reads a required string property. */
export function requireString(props: Record<string, unknown>, name: string): string {
  const v = props[name];
  if (typeof v !== "string" || v === "") throw new Error(`property ${name} is required`);
  return v;
}

/** Reads an optional string property ("" counts as absent). */
export function optionalString(props: Record<string, unknown>, name: string): string | undefined {
  const v = props[name];
  if (v === undefined || v === "") return undefined;
  if (typeof v !== "string") throw new Error(`property ${name} must be a string`);
  return v;
}

/** Reads a list-of-strings property, dropping empty entries. */
export function stringList(props: Record<string, unknown>, name: string): string[] {
  const v = props[name];
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new Error(`property ${name} must be a list of strings`);
  return (v as string[]).map((s) => s.trim()).filter(Boolean);
}

/**
 * Retries `fn` while AWS answers AccessDenied, for up to about a minute: a
 * custom resource can run seconds after CloudFormation attached the IAM
 * policy it needs, before the policy has propagated.
 */
export async function withIamPropagationRetry<T>(fn: () => Promise<T>, attempts = 12, delayMs = 5000): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      const name = (e as Error).name;
      if (attempt >= attempts || (name !== "AccessDeniedException" && name !== "AccessDenied")) throw e;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}
