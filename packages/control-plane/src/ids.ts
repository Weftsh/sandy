/**
 * Identifiers and secrets.
 *
 * Sandbox IDs must match `^[a-z0-9]+$`: the SDKs build hostnames as
 * `<port>-<sandboxId>.<domain>` and split the first label on `-`.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

/** Uniformly random lowercase alphanumeric string (rejection sampling). */
export function randomId(length = 20): string {
  let out = "";
  while (out.length < length) {
    for (const b of randomBytes(length * 2)) {
      if (b < 252) out += ALPHABET[b % 36];
      if (out.length === length) break;
    }
  }
  return out;
}

export const newSandboxId = () => randomId(20);
export const newTemplateId = () => randomId(20);
export const newTeamId = () => `team_${randomId(16)}`;
export const newBuildId = () => randomUUID();
export const newToken = () => randomBytes(32).toString("base64url");

export const API_KEY_PREFIX = "weft_sk_";

export function newApiKey(): string {
  return `${API_KEY_PREFIX}${randomBytes(32).toString("base64url")}`;
}

/** API keys are 256-bit random values, so a plain SHA-256 is a safe verifier. */
export function hashKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export const SANDBOX_ID_RE = /^[a-z0-9]{1,64}$/;
export const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
