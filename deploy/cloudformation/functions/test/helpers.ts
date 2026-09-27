/** Shared test data for the release manifest tests. */
export const D1 = `sha256:${"a".repeat(64)}`;
export const D2 = `sha256:${"b".repeat(64)}`;
export const ZIP_HEX = "c".repeat(64);
export const ZIP_B64 = Buffer.from(ZIP_HEX, "hex").toString("base64");

export function sampleManifest(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    product: "weft-sandboxes",
    version: "1.2.3",
    gitCommit: "0123456789abcdef0123456789abcdef01234567",
    amis: { "us-east-1": "ami-0123456789abcdef0", "eu-west-1": "ami-0fedcba9876543210" },
    images: {
      "control-plane": { repository: "ghcr.io/weftsh/sandbox-control-plane", digest: D1 },
      "egress-gateway": { repository: "ghcr.io/weftsh/sandbox-egress-gateway", digest: D2 },
    },
    artifacts: { "functions/egress-ca.zip": { sha256: ZIP_HEX, size: 1234 } },
    ...overrides,
  };
}

