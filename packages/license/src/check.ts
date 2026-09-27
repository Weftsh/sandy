/**
 * The daily license check.
 *
 * Community, Team and Business installs send one small request a day. It is
 * never in the sandbox path: the control plane runs it on a timer, a failure
 * only records a warning after several days, and the request carries exactly
 * the four fields in {@link CHECK_FIELDS} and nothing else.
 */

/** The complete list of fields that leave the customer account. */
export const CHECK_FIELDS = ["keyId", "version", "region", "peakConcurrent"] as const;

export interface CheckRequest {
  /** License ID from the key (`lid`). */
  keyId: string;
  /** Stack version, e.g. `0.1.0`. */
  version: string;
  /** AWS region the stack runs in. */
  region: string;
  /** Highest number of concurrent sandboxes since the last successful check. */
  peakConcurrent: number;
}

export type RemoteLicenseStatus = "active" | "lapsed" | "revoked" | "unknown";

export interface CheckResponse {
  status: RemoteLicenseStatus;
  /** Optional message from Weft to show admins, e.g. a renewal reminder. */
  notice?: string;
}

export type CheckOutcome =
  | { ok: true; response: CheckResponse; at: Date }
  | { ok: false; error: string; at: Date };

export const DEFAULT_CHECK_ENDPOINT = "https://license.weft.sh/v1/check";

export interface CheckOptions {
  endpoint?: string;
  /** Per-attempt timeout. */
  timeoutMs?: number;
  /** Attempts per check, with exponential backoff between them. */
  attempts?: number;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
}

const MAX_NOTICE_LENGTH = 500;

/** Builds the request body. Only the documented fields are copied. */
export function buildCheckBody(req: CheckRequest): string {
  const body: CheckRequest = {
    keyId: String(req.keyId),
    version: String(req.version),
    region: String(req.region),
    peakConcurrent: Math.max(0, Math.floor(Number(req.peakConcurrent) || 0)),
  };
  return JSON.stringify(body, [...CHECK_FIELDS]);
}

/** Sends one license check. Never throws. */
export async function sendLicenseCheck(req: CheckRequest, opts: CheckOptions = {}): Promise<CheckOutcome> {
  const endpoint = opts.endpoint ?? DEFAULT_CHECK_ENDPOINT;
  const attempts = Math.max(1, opts.attempts ?? 3);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const doFetch = opts.fetch ?? fetch;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.now ?? (() => new Date());
  const body = buildCheckBody(req);

  let lastError = "no attempt made";
  for (let attempt = 0; attempt < attempts; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** attempt);
    try {
      const res = await doFetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": `weft-sandboxes/${req.version}` },
        body,
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "error",
      });
      if (!res.ok) {
        lastError = `license endpoint returned HTTP ${res.status}`;
        if (res.status >= 400 && res.status < 500 && res.status !== 429) break;
        continue;
      }
      const parsed = parseCheckResponse(await res.json());
      if (!parsed) {
        lastError = "license endpoint returned an unrecognized response";
        continue;
      }
      return { ok: true, response: parsed, at: now() };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
  }
  return { ok: false, error: lastError, at: now() };
}

function parseCheckResponse(raw: unknown): CheckResponse | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const statuses: RemoteLicenseStatus[] = ["active", "lapsed", "revoked", "unknown"];
  if (!statuses.includes(r.status as RemoteLicenseStatus)) return null;
  const out: CheckResponse = { status: r.status as RemoteLicenseStatus };
  if (typeof r.notice === "string" && r.notice.length > 0) {
    out.notice = r.notice.slice(0, MAX_NOTICE_LENGTH);
  }
  return out;
}
