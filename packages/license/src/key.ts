/**
 * License key format and local verification.
 *
 * A key is `weft_lic_v1.<payload>.<signature>`, where `payload` is the
 * base64url JSON document below and `signature` is the base64url Ed25519
 * signature over the payload bytes exactly as they appear in the key. Keys are
 * signed with Weft's Ed25519 key in AWS KMS and verified locally against the
 * public keys compiled into the stack. Verification never makes a network call.
 */
import { createPublicKey, verify, type KeyObject } from "node:crypto";

export const KEY_PREFIX = "weft_lic_v1";

export const TIERS = ["community", "team", "business", "enterprise"] as const;
export type Tier = (typeof TIERS)[number];

/** How an install reports to Weft. */
export type LicenseMode =
  /** Daily license check and usage heartbeat. Community, Team and Business. */
  | "online"
  /** No outbound calls. Enterprise air-gapped installs; annual true-up. */
  | "offline";

export interface LicensePayload {
  /** Payload format version. */
  v: 1;
  /** Signing key ID; selects the trusted public key. */
  kid: string;
  /** License ID. This is the "key ID" the daily check reports. */
  lid: string;
  /** Legal entity the license is issued to. */
  entity: string;
  tier: Tier;
  /** AWS account IDs the license covers. Empty means any account. */
  accounts: string[];
  /** Concurrent sandbox cap for the tier; null means unlimited. */
  maxConcurrent: number | null;
  mode: LicenseMode;
  /** Issued-at, ISO 8601. */
  iat: string;
  /** Expiry, ISO 8601. */
  exp: string;
  /** True for 15-day trial keys. */
  trial?: boolean;
}

export type VerifyFailure =
  | "malformed"
  | "unknown_signing_key"
  | "bad_signature"
  | "invalid_payload";

export type VerifyResult =
  | { ok: true; license: LicensePayload }
  | { ok: false; reason: VerifyFailure; detail: string };

/** Public keys trusted to sign licenses, keyed by `kid`. */
export type TrustedKeys = ReadonlyMap<string, KeyObject>;

/** Builds a trusted key map from PEM-encoded SPKI Ed25519 public keys. */
export function trustedKeysFromPem(keys: Record<string, string>): TrustedKeys {
  const map = new Map<string, KeyObject>();
  for (const [kid, pem] of Object.entries(keys)) {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error(`license signing key ${kid} is not an Ed25519 key`);
    }
    map.set(kid, key);
  }
  return map;
}

const MAX_KEY_LENGTH = 8192;

/** Verifies a key's signature and payload shape. Does not check expiry or accounts. */
export function verifyLicenseKey(key: string, trusted: TrustedKeys): VerifyResult {
  const trimmed = key.trim();
  if (trimmed.length > MAX_KEY_LENGTH) {
    return { ok: false, reason: "malformed", detail: "key is too long" };
  }
  const parts = trimmed.split(".");
  if (parts.length !== 3 || parts[0] !== KEY_PREFIX) {
    return { ok: false, reason: "malformed", detail: `key must look like ${KEY_PREFIX}.<payload>.<signature>` };
  }
  const [, payloadPart, sigPart] = parts as [string, string, string];
  if (!isBase64Url(payloadPart) || !isBase64Url(sigPart)) {
    return { ok: false, reason: "malformed", detail: "key segments must be base64url" };
  }
  const payloadBytes = Buffer.from(payloadPart, "base64url");
  const signature = Buffer.from(sigPart, "base64url");

  let raw: unknown;
  try {
    raw = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return { ok: false, reason: "malformed", detail: "payload is not JSON" };
  }
  const kid = typeof raw === "object" && raw !== null ? (raw as { kid?: unknown }).kid : undefined;
  if (typeof kid !== "string") {
    return { ok: false, reason: "malformed", detail: "payload has no kid" };
  }
  const publicKey = trusted.get(kid);
  if (!publicKey) {
    return { ok: false, reason: "unknown_signing_key", detail: `no trusted signing key with id ${kid}` };
  }
  // Signature first: nothing in an unsigned payload is trusted, including the
  // shape checks' error messages.
  if (signature.length !== 64 || !verify(null, Buffer.from(payloadPart, "utf8"), publicKey, signature)) {
    return { ok: false, reason: "bad_signature", detail: "signature does not match" };
  }
  const problem = validatePayload(raw);
  if (problem) {
    return { ok: false, reason: "invalid_payload", detail: problem };
  }
  return { ok: true, license: raw as LicensePayload };
}

function isBase64Url(s: string): boolean {
  return s.length > 0 && /^[A-Za-z0-9_-]+$/.test(s);
}

const ACCOUNT_ID = /^\d{12}$/;

/** Returns a description of the first problem, or null if the payload is valid. */
export function validatePayload(raw: unknown): string | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return "payload must be an object";
  const p = raw as Record<string, unknown>;
  if (p.v !== 1) return "unsupported payload version";
  for (const field of ["kid", "lid", "entity", "iat", "exp"] as const) {
    if (typeof p[field] !== "string" || (p[field] as string).length === 0) return `${field} must be a non-empty string`;
  }
  if (!TIERS.includes(p.tier as Tier)) return `tier must be one of ${TIERS.join(", ")}`;
  if (p.mode !== "online" && p.mode !== "offline") return "mode must be online or offline";
  if (p.mode === "offline" && p.tier !== "enterprise") return "offline keys are issued for the enterprise tier only";
  if (!Array.isArray(p.accounts) || !p.accounts.every((a) => typeof a === "string" && ACCOUNT_ID.test(a))) {
    return "accounts must be a list of 12-digit AWS account IDs";
  }
  if (p.maxConcurrent !== null && !(Number.isInteger(p.maxConcurrent) && (p.maxConcurrent as number) > 0)) {
    return "maxConcurrent must be a positive integer or null";
  }
  if (Number.isNaN(Date.parse(p.iat as string)) || Number.isNaN(Date.parse(p.exp as string))) {
    return "iat and exp must be ISO 8601 timestamps";
  }
  if (Date.parse(p.exp as string) <= Date.parse(p.iat as string)) return "exp must be after iat";
  if (p.trial !== undefined && typeof p.trial !== "boolean") return "trial must be a boolean";
  return null;
}

/** Encodes a signed key from a payload and a signature over the encoded payload. */
export function encodeLicenseKey(payloadPart: string, signature: Uint8Array): string {
  return `${KEY_PREFIX}.${payloadPart}.${Buffer.from(signature).toString("base64url")}`;
}

/** Encodes a payload into the key segment that gets signed. */
export function encodePayload(payload: LicensePayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}
