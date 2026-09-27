/**
 * License status evaluation.
 *
 * There is deliberately no "allowed" flag anywhere in this module. A missing,
 * invalid, expired or over-cap license produces warnings for the admin
 * console, the API and the logs; it never stops a sandbox from launching or
 * running. Weft's enforcement levers are release access and the contract.
 */
import type { LicensePayload, Tier, VerifyFailure } from "./key.js";

/** Days before expiry at which the stack starts warning. */
export const EXPIRY_WARNING_DAYS = 30;
/** Days after expiry at which Weft stops sharing new releases with the account. */
export const RELEASE_GRACE_DAYS = 30;
/** Days without a successful online check before the stack warns. */
export const CHECK_OVERDUE_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

export type LicenseState =
  /** No license configured. */
  | "unlicensed"
  /** A key is configured but fails verification or names other accounts. */
  | "invalid"
  | "active"
  /** Active, and expires within {@link EXPIRY_WARNING_DAYS}. */
  | "expiring"
  /** Past its expiry date. Running and new sandboxes are unaffected. */
  | "lapsed";

export interface LicenseStatus {
  state: LicenseState;
  source: "key" | "marketplace" | "none";
  tier: Tier | null;
  licenseId: string | null;
  entity: string | null;
  mode: "online" | "offline" | "marketplace" | null;
  expiresAt: string | null;
  maxConcurrent: number | null;
  /** Whether the current AWS account is covered; null when unknown. */
  accountCovered: boolean | null;
  /**
   * Whether this account should still receive new signed releases and
   * security patches. Informational: Weft enforces it by sharing images only
   * with covered accounts.
   */
  releaseAccess: boolean;
  /** Online mode only: no successful daily check for {@link CHECK_OVERDUE_DAYS}. */
  checkOverdue: boolean;
  /** Current concurrent sandboxes exceed the tier cap. Never blocks launches. */
  overCap: boolean;
  /** Plain-language messages for the console banner, API and logs. */
  warnings: string[];
}

export interface EvaluateInput {
  now: Date;
  /** Verified key, or the verification failure, or undefined when no key is set. */
  key?: { ok: true; license: LicensePayload } | { ok: false; reason: VerifyFailure; detail: string };
  /** Marketplace entitlement, when the install uses AWS License Manager. */
  marketplace?: { ok: true; expiresAt: string | null } | { ok: false; detail: string };
  /** The AWS account the stack runs in, if known. */
  accountId?: string;
  /** Concurrent sandboxes right now. */
  concurrentSandboxes: number;
  /** When the stack was installed; used to avoid "overdue" warnings on day one. */
  installedAt?: Date;
  /** Last successful online check, if any. */
  lastCheckAt?: Date;
  /** Status reported by the last successful check. */
  lastCheckStatus?: "active" | "lapsed" | "revoked" | "unknown";
}

export function evaluateLicense(input: EvaluateInput): LicenseStatus {
  const status: LicenseStatus = {
    state: "unlicensed",
    source: "none",
    tier: null,
    licenseId: null,
    entity: null,
    mode: null,
    expiresAt: null,
    maxConcurrent: null,
    accountCovered: null,
    releaseAccess: false,
    checkOverdue: false,
    overCap: false,
    warnings: [],
  };

  if (input.marketplace) {
    status.source = "marketplace";
    status.mode = "marketplace";
    if (!input.marketplace.ok) {
      status.state = "invalid";
      status.warnings.push(`AWS Marketplace license check failed: ${input.marketplace.detail}`);
      return status;
    }
    status.tier = "enterprise";
    status.accountCovered = true;
    status.expiresAt = input.marketplace.expiresAt;
    applyExpiry(status, input.now);
    return status;
  }

  if (!input.key) {
    status.warnings.push("No license key is configured. Sandboxes run normally; add a key to receive signed updates.");
    return status;
  }
  status.source = "key";
  if (!input.key.ok) {
    status.state = "invalid";
    status.warnings.push(`The license key could not be verified (${input.key.reason}): ${input.key.detail}`);
    return status;
  }

  const lic = input.key.license;
  status.tier = lic.tier;
  status.licenseId = lic.lid;
  status.entity = lic.entity;
  status.mode = lic.mode;
  status.expiresAt = lic.exp;
  status.maxConcurrent = lic.maxConcurrent;

  if (lic.accounts.length > 0 && input.accountId) {
    status.accountCovered = lic.accounts.includes(input.accountId);
    if (!status.accountCovered) {
      status.state = "invalid";
      status.releaseAccess = false;
      status.warnings.push(
        `This license covers AWS accounts ${lic.accounts.join(", ")}, not ${input.accountId}. Contact Weft to add this account.`,
      );
      return status;
    }
  } else if (lic.accounts.length === 0) {
    status.accountCovered = true;
  }

  applyExpiry(status, input.now);

  if (lic.maxConcurrent !== null && input.concurrentSandboxes > lic.maxConcurrent) {
    status.overCap = true;
    status.warnings.push(
      `${input.concurrentSandboxes} sandboxes are running; the ${lic.tier} tier covers ${lic.maxConcurrent}. ` +
        "Sandboxes keep launching. Two consecutive months over the cap lead to a notice to reduce usage or change tier.",
    );
  }

  if (lic.mode === "online") {
    const reference = input.lastCheckAt ?? input.installedAt;
    if (reference && input.now.getTime() - reference.getTime() > CHECK_OVERDUE_DAYS * DAY_MS) {
      status.checkOverdue = true;
      status.warnings.push(
        `The daily license check has not succeeded for more than ${CHECK_OVERDUE_DAYS} days. ` +
          "Sandboxes are unaffected; check outbound HTTPS access to the license endpoint.",
      );
    }
    if (input.lastCheckStatus === "revoked") {
      status.releaseAccess = false;
      status.warnings.push("Weft reports this license as revoked. Running sandboxes are unaffected.");
    }
  }
  return status;
}

function applyExpiry(status: LicenseStatus, now: Date): void {
  if (!status.expiresAt) {
    status.state = "active";
    status.releaseAccess = true;
    return;
  }
  const msLeft = Date.parse(status.expiresAt) - now.getTime();
  if (msLeft <= 0) {
    const daysLapsed = Math.floor(-msLeft / DAY_MS);
    status.state = "lapsed";
    status.releaseAccess = daysLapsed < RELEASE_GRACE_DAYS;
    status.warnings.push(
      status.releaseAccess
        ? `The license expired ${daysLapsed} day(s) ago. Sandboxes are unaffected. New releases and security patches stop ${RELEASE_GRACE_DAYS - daysLapsed} day(s) from now unless it is renewed.`
        : "The license has lapsed. Sandboxes are unaffected, but this account no longer receives new releases or security patches.",
    );
    return;
  }
  status.releaseAccess = true;
  const daysLeft = Math.ceil(msLeft / DAY_MS);
  if (daysLeft <= EXPIRY_WARNING_DAYS) {
    status.state = "expiring";
    status.warnings.push(`The license expires in ${daysLeft} day(s).`);
  } else {
    status.state = "active";
  }
}
