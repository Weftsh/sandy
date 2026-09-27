/**
 * Licensing inside the stack.
 *
 * Nothing here can stop a sandbox. The key is verified locally; online keys
 * send one daily check with exactly four fields (license ID, stack version,
 * region, peak concurrency); Marketplace installs check out an AWS License
 * Manager entitlement in the customer's own account and contact no one.
 */
import { randomUUID } from "node:crypto";

import { LicenseManagerClient } from "@aws-sdk/client-license-manager";
import {
  RELEASE_SIGNING_KEYS,
  checkoutMarketplaceLicense,
  evaluateLicense,
  sendLicenseCheck,
  trustedKeysFromPem,
  verifyLicenseKey,
  type LicenseStatus,
  type RemoteLicenseStatus,
  type TrustedKeys,
  type VerifyResult,
} from "@weftsh/sandbox-license";

import { badRequest } from "../errors.js";
import type { Logger } from "../log.js";
import type { Store } from "../store/types.js";

interface LicenseState {
  key?: string;
  /** The configured (stack parameter) key last applied, so a key installed
   * through the API is replaced only when the parameter changes. */
  configuredKey?: string;
  installedAt: string;
  lastCheckAt?: string;
  lastCheckStatus?: RemoteLicenseStatus;
  notice?: string;
  lastCheckError?: string;
  marketplace?: { ok: true; expiresAt: string | null } | { ok: false; detail: string };
}

interface UsageState {
  peakSinceCheck: number;
  /** Peak concurrent sandboxes per calendar month (UTC), `YYYY-MM`. */
  monthly: Record<string, number>;
  current: number;
}

export interface LicenseServiceOptions {
  version: string;
  region: string;
  configuredKey?: string;
  mode: "key" | "marketplace";
  marketplace?: { productSku: string; entitlementName: string };
  endpoint?: string;
  extraPublicKeys: Record<string, string>;
  accountId?: () => Promise<string | undefined>;
  fetch?: typeof fetch;
  /** Wait between check retries; injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
  licenseManager?: Pick<LicenseManagerClient, "send">;
}

const STATE_KEY = "license";
const USAGE_KEY = "usage";

export class LicenseService {
  private trusted: TrustedKeys;
  private accountId: string | undefined;
  private lastWarnings = "";

  constructor(
    private store: Store,
    private opts: LicenseServiceOptions,
    private log: Logger,
  ) {
    this.trusted = trustedKeysFromPem({ ...RELEASE_SIGNING_KEYS, ...opts.extraPublicKeys });
  }

  async init(): Promise<void> {
    const state = await this.state();
    const configured = this.opts.configuredKey?.trim();
    if (configured && state.configuredKey !== configured) {
      state.key = configured;
      state.configuredKey = configured;
      await this.store.putMeta(STATE_KEY, state);
    }
    this.accountId = await this.opts.accountId?.().catch(() => undefined);
  }

  private async state(): Promise<LicenseState> {
    return (await this.store.getMeta<LicenseState>(STATE_KEY)) ?? { installedAt: new Date().toISOString() };
  }

  private async usage(): Promise<UsageState> {
    return (await this.store.getMeta<UsageState>(USAGE_KEY)) ?? { peakSinceCheck: 0, monthly: {}, current: 0 };
  }

  private verify(key: string | undefined): VerifyResult | undefined {
    return key ? verifyLicenseKey(key, this.trusted) : undefined;
  }

  /** Installs a new key after checking it verifies. */
  async installKey(key: string): Promise<LicenseStatus> {
    const result = this.verify(key);
    if (!result?.ok) throw badRequest(`license key rejected: ${result?.detail ?? "empty key"}`);
    const state = await this.state();
    state.key = key.trim();
    state.lastCheckAt = undefined;
    state.lastCheckStatus = undefined;
    await this.store.putMeta(STATE_KEY, state);
    this.log.info("license key installed", { licenseId: result.license.lid, tier: result.license.tier });
    return this.status();
  }

  async status(
    now = new Date(),
  ): Promise<LicenseStatus & { notice?: string; peakThisMonth: number; monthlyPeaks: Record<string, number> }> {
    const state = await this.state();
    const usage = await this.usage();
    const status = evaluateLicense({
      now,
      key: this.opts.mode === "marketplace" ? undefined : this.verify(state.key),
      marketplace: this.opts.mode === "marketplace" ? (state.marketplace ?? { ok: false, detail: "not checked yet" }) : undefined,
      accountId: this.accountId,
      concurrentSandboxes: usage.current,
      installedAt: new Date(state.installedAt),
      lastCheckAt: state.lastCheckAt ? new Date(state.lastCheckAt) : undefined,
      lastCheckStatus: state.lastCheckStatus,
    });
    const warnings = status.warnings.join(" | ");
    if (warnings !== this.lastWarnings) {
      this.lastWarnings = warnings;
      if (warnings) this.log.warn("license attention needed", { warnings: status.warnings });
    }
    // Monthly peaks (UTC, last 13 months) are what an offline license's annual
    // true-up reports.
    return { ...status, notice: state.notice, peakThisMonth: usage.monthly[monthKey(now)] ?? 0, monthlyPeaks: { ...usage.monthly } };
  }

  /** Records the current number of running sandboxes. */
  async recordConcurrency(running: number, now = new Date()): Promise<void> {
    const usage = await this.usage();
    usage.current = running;
    usage.peakSinceCheck = Math.max(usage.peakSinceCheck, running);
    const m = monthKey(now);
    usage.monthly[m] = Math.max(usage.monthly[m] ?? 0, running);
    // Keep 13 months for the annual true-up.
    for (const k of Object.keys(usage.monthly).sort().slice(0, -13)) delete usage.monthly[k];
    await this.store.putMeta(USAGE_KEY, usage);
  }

  /** The daily check (or Marketplace checkout). Never throws. */
  async runCheck(): Promise<void> {
    try {
      const state = await this.state();
      if (this.opts.mode === "marketplace") {
        if (!this.opts.marketplace?.productSku) {
          state.marketplace = { ok: false, detail: "WEFT_MARKETPLACE_PRODUCT_SKU is not set" };
        } else {
          const client = this.opts.licenseManager ?? new LicenseManagerClient({ region: this.opts.region });
          state.marketplace = await checkoutMarketplaceLicense(client, this.opts.marketplace, randomUUID());
        }
        await this.store.putMeta(STATE_KEY, state);
        return;
      }
      const verified = this.verify(state.key);
      if (!verified?.ok || verified.license.mode !== "online") return;
      const usage = await this.usage();
      const outcome = await sendLicenseCheck(
        { keyId: verified.license.lid, version: this.opts.version, region: this.opts.region, peakConcurrent: usage.peakSinceCheck },
        { endpoint: this.opts.endpoint, fetch: this.opts.fetch, sleep: this.opts.sleep },
      );
      if (outcome.ok) {
        state.lastCheckAt = outcome.at.toISOString();
        state.lastCheckStatus = outcome.response.status;
        state.notice = outcome.response.notice;
        state.lastCheckError = undefined;
        usage.peakSinceCheck = usage.current;
        await this.store.putMeta(USAGE_KEY, usage);
      } else {
        state.lastCheckError = outcome.error;
        this.log.warn("license check failed; sandboxes are unaffected", { error: outcome.error });
      }
      await this.store.putMeta(STATE_KEY, state);
    } catch (e) {
      this.log.warn("license check errored; sandboxes are unaffected", { error: String(e) });
    }
  }
}

function monthKey(d: Date): string {
  return d.toISOString().slice(0, 7);
}
