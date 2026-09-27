/**
 * Enterprise licensing through AWS Marketplace.
 *
 * Marketplace contract purchases create a license in the buyer's own account.
 * The stack checks it out through the AWS License Manager API, so the check
 * stays inside the customer's account and nothing is sent to Weft.
 */
import {
  CheckoutLicenseCommand,
  type CheckoutLicenseCommandOutput,
  type LicenseManagerClient,
} from "@aws-sdk/client-license-manager";

/** Issuer fingerprint AWS Marketplace uses for every seller. */
export const MARKETPLACE_KEY_FINGERPRINT = "aws:294406891311:AWS/Marketplace:issuer-fingerprint";

export interface MarketplaceConfig {
  /** Product SKU (the Marketplace product ID). */
  productSku: string;
  /** Entitlement name defined in the Marketplace listing. */
  entitlementName: string;
  keyFingerprint?: string;
}

export type MarketplaceResult =
  | { ok: true; expiresAt: string | null; licenseArn: string | null }
  | { ok: false; detail: string };

type Sender = Pick<LicenseManagerClient, "send">;

/** Checks out the Marketplace entitlement. Never throws. */
export async function checkoutMarketplaceLicense(
  client: Sender,
  cfg: MarketplaceConfig,
  clientToken: string,
): Promise<MarketplaceResult> {
  try {
    const out = (await client.send(
      new CheckoutLicenseCommand({
        ProductSKU: cfg.productSku,
        CheckoutType: "PROVISIONAL",
        KeyFingerprint: cfg.keyFingerprint ?? MARKETPLACE_KEY_FINGERPRINT,
        Entitlements: [{ Name: cfg.entitlementName, Unit: "None" }],
        ClientToken: clientToken,
      }),
    )) as CheckoutLicenseCommandOutput;
    const allowed = out.EntitlementsAllowed ?? [];
    if (!allowed.some((e) => e.Name === cfg.entitlementName)) {
      return { ok: false, detail: `entitlement ${cfg.entitlementName} was not granted` };
    }
    return {
      ok: true,
      expiresAt: out.Expiration ? new Date(out.Expiration).toISOString() : null,
      licenseArn: out.LicenseArn ?? null,
    };
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, detail: `${name}: ${message}` };
  }
}
