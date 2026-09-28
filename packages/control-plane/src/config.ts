/**
 * Control plane configuration, read once from the environment.
 *
 * Production values come from the CloudFormation stack (task definition
 * environment and Secrets Manager secrets). Development-only switches are
 * refused unless WEFT_DEV_MODE=1.
 */
import { readFileSync } from "node:fs";

export type Role = "api" | "edge" | "worker";

export interface Config {
  roles: Set<Role>;
  version: string;
  devMode: boolean;
  apiListen: { host: string; port: number };
  edgeListen: { host: string; port: number };
  /** Domain clients set as E2B_DOMAIN; sandboxes are `<port>-<id>.<domain>`. */
  domain: string;
  region: string;
  store: { kind: "memory" } | { kind: "dynamodb"; tablePrefix: string; endpoint?: string };
  /** S3 bucket for template artifacts and pause snapshots (Firecracker hosts). */
  artifactsBucket?: string;
  /** Development only: keep artifacts in this directory, served by the API. */
  devArtifactsDir?: string;
  internalAuth:
    | { kind: "dev-token"; token: string }
    | { kind: "aws-iam"; serverId: string; hostRoleName: string; gatewayRoleName: string; accountId?: string };
  /** Plaintext admin key to ensure exists at startup (from Secrets Manager). */
  bootstrapAdminKey?: string;
  /** name=image pairs built as public templates when missing. */
  bootstrapTemplates: { name: string; image: string }[];
  defaults: { timeoutSec: number; maxTimeoutSec: number; vcpus: number; memoryMib: number; diskMib: number };
  pausedRetentionDays: number;
  /** PEM of the egress gateway's interception CA, injected into sandboxes that use credentials. */
  egressCaCert?: string;
  license: {
    key?: string;
    mode: "key" | "marketplace";
    marketplace?: { productSku: string; entitlementName: string };
    endpoint?: string;
    devPublicKeys: Record<string, string>;
  };
  metricsNamespace?: string;
  edgeTls?: { certPem: string; keyPem: string };
  /** Registry host (e.g. ECR) whose credentials the control plane can mint for template builds. */
  ecrRegistry?: string;
}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === "" ? undefined : v;
}

function listen(value: string, name: string): { host: string; port: number } {
  const idx = value.lastIndexOf(":");
  const port = Number(value.slice(idx + 1));
  if (idx <= 0 || !Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`${name} must be host:port, got ${value}`);
  }
  return { host: value.slice(0, idx), port };
}

function int(name: string, fallback: number, min: number, max: number): number {
  const raw = env(name);
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer in ${min}..${max}`);
  return n;
}

function fileOrValue(valueVar: string, fileVar: string): string | undefined {
  const file = env(fileVar);
  if (file) return readFileSync(file, "utf8");
  return env(valueVar);
}

export function loadConfig(): Config {
  const devMode = env("WEFT_DEV_MODE") === "1";
  const artifactsBucket = env("WEFT_ARTIFACTS_BUCKET");
  const devArtifactsDir = env("WEFT_DEV_ARTIFACTS_DIR");
  if (devArtifactsDir && !devMode) throw new Error("WEFT_DEV_ARTIFACTS_DIR requires WEFT_DEV_MODE=1");
  if (devArtifactsDir && artifactsBucket) throw new Error("set WEFT_ARTIFACTS_BUCKET or WEFT_DEV_ARTIFACTS_DIR, not both");

  const roles = new Set(
    (env("WEFT_ROLES") ?? "api,edge,worker").split(",").map((r) => r.trim()) as Role[],
  );
  for (const r of roles) {
    if (!["api", "edge", "worker"].includes(r)) throw new Error(`unknown role ${r} in WEFT_ROLES`);
  }
  const domain = env("WEFT_DOMAIN");
  if (!domain) throw new Error("WEFT_DOMAIN is required (the domain clients use as E2B_DOMAIN)");
  if (!/^[a-z0-9.-]+(:\d{1,5})?$/.test(domain) || (domain.includes(":") && !devMode)) {
    throw new Error("WEFT_DOMAIN must be a lowercase DNS name (a :port suffix is allowed in development only)");
  }
  if (["e2b.app", "e2b.dev", "e2b.pro", "e2b-staging.dev"].includes(domain)) {
    throw new Error("WEFT_DOMAIN must be your own domain; the E2B SDKs special-case E2B's domains");
  }

  const storeKind = env("WEFT_STORE") ?? (devMode ? "memory" : "dynamodb");
  let store: Config["store"];
  if (storeKind === "memory") {
    if (!devMode) throw new Error("WEFT_STORE=memory is for development only (set WEFT_DEV_MODE=1)");
    store = { kind: "memory" };
  } else if (storeKind === "dynamodb") {
    store = { kind: "dynamodb", tablePrefix: env("WEFT_TABLE_PREFIX") ?? "weft-", endpoint: env("WEFT_DYNAMODB_ENDPOINT") };
  } else {
    throw new Error(`unknown WEFT_STORE ${storeKind}`);
  }

  const authKind = env("WEFT_INTERNAL_AUTH") ?? (devMode ? "dev-token" : "aws-iam");
  let internalAuth: Config["internalAuth"];
  if (authKind === "dev-token") {
    const token = env("WEFT_DEV_TOKEN");
    if (!devMode) throw new Error("WEFT_INTERNAL_AUTH=dev-token requires WEFT_DEV_MODE=1");
    if (!token || token.length < 16) throw new Error("WEFT_DEV_TOKEN must be at least 16 characters");
    internalAuth = { kind: "dev-token", token };
  } else if (authKind === "aws-iam") {
    const hostRoleName = env("WEFT_HOST_ROLE_NAME");
    const gatewayRoleName = env("WEFT_GATEWAY_ROLE_NAME");
    if (!hostRoleName || !gatewayRoleName) {
      throw new Error("WEFT_HOST_ROLE_NAME and WEFT_GATEWAY_ROLE_NAME are required with aws-iam internal auth");
    }
    internalAuth = {
      kind: "aws-iam",
      serverId: env("WEFT_SERVER_ID") ?? "weft-control-plane",
      hostRoleName,
      gatewayRoleName,
      accountId: env("WEFT_AWS_ACCOUNT_ID"),
    };
  } else {
    throw new Error(`unknown WEFT_INTERNAL_AUTH ${authKind}`);
  }

  const bootstrapTemplates = (env("WEFT_BOOTSTRAP_TEMPLATES") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq <= 0) throw new Error(`WEFT_BOOTSTRAP_TEMPLATES entries must be name=image, got ${pair}`);
      return { name: pair.slice(0, eq), image: pair.slice(eq + 1) };
    });

  let devPublicKeys: Record<string, string> = {};
  const devKeys = env("WEFT_DEV_LICENSE_PUBLIC_KEYS");
  if (devKeys) {
    if (!devMode) throw new Error("WEFT_DEV_LICENSE_PUBLIC_KEYS requires WEFT_DEV_MODE=1");
    devPublicKeys = JSON.parse(devKeys) as Record<string, string>;
  }
  const licenseMode = env("WEFT_LICENSE_MODE") ?? "key";
  if (licenseMode !== "key" && licenseMode !== "marketplace") throw new Error("WEFT_LICENSE_MODE must be key or marketplace");
  const endpoint = env("WEFT_LICENSE_ENDPOINT");
  if (endpoint && !devMode && !endpoint.startsWith("https://")) throw new Error("WEFT_LICENSE_ENDPOINT must be HTTPS");

  const certPem = fileOrValue("WEFT_EDGE_TLS_CERT", "WEFT_EDGE_TLS_CERT_FILE");
  const keyPem = fileOrValue("WEFT_EDGE_TLS_KEY", "WEFT_EDGE_TLS_KEY_FILE");

  return {
    roles,
    version: env("WEFT_VERSION") ?? "0.1.0",
    devMode,
    apiListen: listen(env("WEFT_API_LISTEN") ?? "0.0.0.0:3000", "WEFT_API_LISTEN"),
    edgeListen: listen(env("WEFT_EDGE_LISTEN") ?? "0.0.0.0:3001", "WEFT_EDGE_LISTEN"),
    domain,
    region: env("AWS_REGION") ?? env("AWS_DEFAULT_REGION") ?? "us-east-1",
    store,
    artifactsBucket,
    devArtifactsDir,
    internalAuth,
    bootstrapAdminKey: env("WEFT_BOOTSTRAP_ADMIN_KEY"),
    bootstrapTemplates,
    defaults: {
      timeoutSec: int("WEFT_DEFAULT_TIMEOUT_SEC", 300, 1, 86_400),
      maxTimeoutSec: int("WEFT_MAX_TIMEOUT_SEC", 86_400, 1, 30 * 86_400),
      vcpus: int("WEFT_DEFAULT_VCPUS", 2, 1, 64),
      memoryMib: int("WEFT_DEFAULT_MEMORY_MIB", 512, 128, 262_144),
      diskMib: int("WEFT_DEFAULT_DISK_MIB", 4096, 512, 1_048_576),
    },
    pausedRetentionDays: int("WEFT_PAUSED_RETENTION_DAYS", 30, 1, 3650),
    egressCaCert: fileOrValue("WEFT_EGRESS_CA_CERT", "WEFT_EGRESS_CA_CERT_FILE"),
    license: {
      key: env("WEFT_LICENSE_KEY"),
      mode: licenseMode,
      marketplace:
        licenseMode === "marketplace"
          ? {
              productSku: env("WEFT_MARKETPLACE_PRODUCT_SKU") ?? "",
              entitlementName: env("WEFT_MARKETPLACE_ENTITLEMENT") ?? "Enterprise",
            }
          : undefined,
      endpoint,
      devPublicKeys,
    },
    metricsNamespace: env("WEFT_METRICS_NAMESPACE"),
    edgeTls: certPem && keyPem ? { certPem, keyPem } : undefined,
    ecrRegistry: env("WEFT_ECR_REGISTRY"),
  };
}
