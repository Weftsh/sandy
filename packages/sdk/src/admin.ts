/**
 * Client for the Weft administration API (`/weft/v1`).
 *
 * Sandboxes themselves are created with the unmodified E2B SDK; this client
 * covers what E2B's API has no equivalent for: teams, API keys, egress
 * policies, image templates, the license and the host fleet.
 */

export interface AllowRule {
  /** `api.github.com`, `*.pypi.org`, `*` (any public host) or a CIDR block. */
  host: string;
  /** Destination ports; defaults to 80 and 443. */
  ports?: number[];
}

export interface CredentialRule {
  /** Exact hostname the credential is injected for (HTTPS only). */
  host: string;
  /** Header to set, e.g. `authorization`. */
  header: string;
  /** AWS Secrets Manager secret ARN or name. The secret must carry the tag `weft-sandbox-access=true`. */
  secretId: string;
  /** Key to read when the secret is a JSON object. */
  secretKey?: string;
  /** Header value template, e.g. `Bearer {{secret}}`. Defaults to `{{secret}}`. */
  format?: string;
}

export interface EgressPolicy {
  allow?: AllowRule[];
  credentials?: CredentialRule[];
}

export interface Team {
  teamId: string;
  name: string;
  createdAt: string;
  egressPolicy: Required<EgressPolicy>;
}

export interface ApiKeyInfo {
  keyId: string;
  teamId: string;
  role: "team" | "admin";
  name: string;
  prefix: string;
  createdAt: string;
}

export interface TemplateInfo {
  templateId: string;
  names: string[];
  public: boolean;
  teamId: string | null;
  image: string;
  status: "building" | "ready" | "error";
  buildId: string | null;
  latestBuildId: string;
  cpuCount: number;
  memoryMB: number;
  diskSizeMB: number;
  envdVersion?: string;
  error?: string;
  createdAt: string;
  updatedAt: string;
  logs?: string[];
}

export interface TemplateBuildOptions {
  name: string;
  /** Image reference, e.g. an image in the stack's ECR repository. */
  image: string;
  cpuCount?: number;
  memoryMB?: number;
  diskSizeMB?: number;
  envVars?: Record<string, string>;
  defaultWorkdir?: string;
  /** Runs in the background before the template's snapshot is taken. */
  startCmd?: string;
  /** Polled until it exits 0 before the snapshot is taken. */
  readyCmd?: string;
  /** Admin only: usable by every team. */
  public?: boolean;
  /** Credentials for a private registry other than the stack's ECR. */
  registry?: { username: string; password: string };
}

export interface LicenseStatus {
  state: "unlicensed" | "invalid" | "active" | "expiring" | "lapsed";
  source: "key" | "marketplace" | "none";
  tier: string | null;
  licenseId: string | null;
  entity: string | null;
  expiresAt: string | null;
  maxConcurrent: number | null;
  releaseAccess: boolean;
  checkOverdue: boolean;
  overCap: boolean;
  warnings: string[];
  notice?: string;
  peakThisMonth: number;
  /** Peak concurrent sandboxes per UTC month (`YYYY-MM`), last 13 months. */
  monthlyPeaks?: Record<string, number>;
}

export class WeftApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "WeftApiError";
  }
}

export interface WeftAdminOptions {
  /** The stack's API URL, e.g. `https://api.sandbox.example.com`. Defaults to E2B_API_URL. */
  apiUrl?: string;
  /** An admin key (or a team key for team-scoped calls). Defaults to WEFT_API_KEY, then E2B_API_KEY. */
  apiKey?: string;
  fetch?: typeof fetch;
}

export class WeftAdmin {
  private apiUrl: string;
  private apiKey: string;
  private doFetch: typeof fetch;

  constructor(opts: WeftAdminOptions = {}) {
    const apiUrl = opts.apiUrl ?? process.env.WEFT_API_URL ?? process.env.E2B_API_URL;
    const apiKey = opts.apiKey ?? process.env.WEFT_API_KEY ?? process.env.E2B_API_KEY;
    if (!apiUrl) throw new Error("apiUrl is required (or set WEFT_API_URL / E2B_API_URL)");
    if (!apiKey) throw new Error("apiKey is required (or set WEFT_API_KEY / E2B_API_KEY)");
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.doFetch = opts.fetch ?? fetch;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.doFetch(`${this.apiUrl}${path}`, {
      method,
      headers: {
        "x-api-key": this.apiKey,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      let message = text || res.statusText;
      try {
        message = (JSON.parse(text) as { message?: string }).message ?? message;
      } catch {
        // not JSON
      }
      throw new WeftApiError(res.status, `${method} ${path}: ${res.status} ${message}`);
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }

  license = {
    status: () => this.call<LicenseStatus>("GET", "/weft/v1/license"),
    install: (key: string) => this.call<LicenseStatus>("PUT", "/weft/v1/license", { key }),
  };

  teams = {
    list: () => this.call<Team[]>("GET", "/weft/v1/teams"),
    get: (teamId: string) => this.call<Team>("GET", `/weft/v1/teams/${encodeURIComponent(teamId)}`),
    /** Creates a team and its first API key. The key is returned only once. */
    create: (name: string) =>
      this.call<{ team: Team; apiKey: { keyId: string; key: string } }>("POST", "/weft/v1/teams", { name }),
    setEgressPolicy: (teamId: string, policy: EgressPolicy) =>
      this.call<Team>("PUT", `/weft/v1/teams/${encodeURIComponent(teamId)}/egress`, policy),
  };

  apiKeys = {
    list: (teamId: string) => this.call<ApiKeyInfo[]>("GET", `/weft/v1/teams/${encodeURIComponent(teamId)}/api-keys`),
    /** Creates a key. The plaintext is returned only once. */
    create: (teamId: string, name: string) =>
      this.call<{ keyId: string; key: string }>("POST", `/weft/v1/teams/${encodeURIComponent(teamId)}/api-keys`, { name }),
    revoke: (teamId: string, keyId: string) =>
      this.call<void>("DELETE", `/weft/v1/teams/${encodeURIComponent(teamId)}/api-keys/${encodeURIComponent(keyId)}`),
  };

  templates = {
    list: () => this.call<TemplateInfo[]>("GET", "/weft/v1/templates"),
    get: (templateId: string) => this.call<TemplateInfo>("GET", `/weft/v1/templates/${encodeURIComponent(templateId)}`),
    build: (opts: TemplateBuildOptions) => this.call<TemplateInfo>("POST", "/weft/v1/templates", opts),
    rebuild: (templateId: string, opts: Partial<TemplateBuildOptions> = {}) =>
      this.call<TemplateInfo>("POST", `/weft/v1/templates/${encodeURIComponent(templateId)}/rebuild`, opts),
    delete: (templateId: string) => this.call<void>("DELETE", `/weft/v1/templates/${encodeURIComponent(templateId)}`),
    /** Polls until the template's latest build finishes. */
    waitUntilReady: async (templateId: string, opts: { timeoutMs?: number; intervalMs?: number; onLog?: (line: string) => void } = {}) => {
      const deadline = Date.now() + (opts.timeoutMs ?? 30 * 60_000);
      let printed = 0;
      for (;;) {
        const t = await this.templates.get(templateId);
        for (const line of (t.logs ?? []).slice(printed)) opts.onLog?.(line);
        printed = Math.max(printed, t.logs?.length ?? 0);
        if (t.status === "ready" && t.buildId === t.latestBuildId) return t;
        if (t.status !== "building") throw new WeftApiError(422, `template build failed: ${t.error ?? t.status}`);
        if (Date.now() > deadline) throw new WeftApiError(408, "timed out waiting for the template build");
        await new Promise((r) => setTimeout(r, opts.intervalMs ?? 2000));
      }
    },
  };

  hosts = {
    list: () => this.call<Record<string, unknown>[]>("GET", "/weft/v1/hosts"),
  };

  sandboxes = {
    list: () => this.call<Record<string, unknown>[]>("GET", "/weft/v1/sandboxes"),
  };
}
