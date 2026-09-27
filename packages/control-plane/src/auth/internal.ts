/**
 * Authentication of host agents and the egress gateway (see `crates/awsauth`).
 *
 * The caller sends a signed-but-unsent STS `GetCallerIdentity` request in
 * `X-Weft-Internal-Auth`. The control plane checks that it is exactly the
 * request it expects (URL, body, a signed `x-weft-server-id` naming this
 * control plane), replays it to STS, and maps the returned role ARN to a
 * host (session name = instance ID) or to the gateway. The URL called is
 * always built here, never taken from the header.
 */
import { createHash } from "node:crypto";

import { forbidden, unauthorized } from "../errors.js";
import { safeEqual } from "../ids.js";

export const INTERNAL_AUTH_HEADER = "x-weft-internal-auth";
const STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
const ALLOWED_HEADERS = new Set([
  "host",
  "content-type",
  "x-amz-date",
  "x-amz-security-token",
  "authorization",
  "x-weft-server-id",
  "x-amz-content-sha256",
]);

export type InternalIdentity = { kind: "host"; hostId: string } | { kind: "gateway" } | { kind: "dev" };

export interface InternalAuthConfig {
  kind: "dev-token" | "aws-iam";
  devToken?: string;
  serverId?: string;
  region?: string;
  accountId?: string;
  hostRoleName?: string;
  gatewayRoleName?: string;
}

interface SignedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

export class InternalAuth {
  private cache = new Map<string, { identity: InternalIdentity; until: number }>();

  constructor(
    private cfg: InternalAuthConfig,
    private doFetch: typeof fetch = fetch,
  ) {}

  async verify(header: string | undefined): Promise<InternalIdentity> {
    if (!header) throw unauthorized("missing internal credentials");
    if (this.cfg.kind === "dev-token") {
      const token = header.startsWith("dev-token ") ? header.slice(10) : "";
      if (!this.cfg.devToken || !safeEqual(token, this.cfg.devToken)) throw unauthorized("invalid internal credentials");
      return { kind: "dev" };
    }
    if (!header.startsWith("aws-iam ")) throw unauthorized("expected aws-iam credentials");
    const digest = createHash("sha256").update(header).digest("hex");
    const hit = this.cache.get(digest);
    if (hit && hit.until > Date.now()) return hit.identity;

    const signed = this.parse(header.slice(8));
    const arn = await this.callSts(signed);
    const identity = this.identityFromArn(arn);
    if (this.cache.size > 5000) this.cache.clear();
    // Signed requests are valid at STS for 15 minutes; trust the result for 2.
    this.cache.set(digest, { identity, until: Date.now() + 120_000 });
    return identity;
  }

  private parse(encoded: string): SignedRequest {
    let raw: unknown;
    try {
      raw = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    } catch {
      throw unauthorized("malformed internal credentials");
    }
    const r = raw as Partial<SignedRequest>;
    if (typeof r !== "object" || r === null || typeof r.url !== "string" || typeof r.body !== "string" || typeof r.headers !== "object" || r.headers === null) {
      throw unauthorized("malformed internal credentials");
    }
    const region = this.cfg.region ?? "us-east-1";
    const expectedUrls = [`https://sts.${region}.amazonaws.com/`, "https://sts.amazonaws.com/"];
    if (r.method !== "POST" || !expectedUrls.includes(r.url) || r.body !== STS_BODY) {
      throw unauthorized("unexpected signed request");
    }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(r.headers)) {
      const name = k.toLowerCase();
      if (!ALLOWED_HEADERS.has(name)) throw unauthorized(`unexpected header ${name} in signed request`);
      if (typeof v !== "string") throw unauthorized("malformed internal credentials");
      headers[name] = v;
    }
    if (headers.host !== new URL(r.url).host) throw unauthorized("signed host does not match");
    if (headers["x-weft-server-id"] !== this.cfg.serverId) throw unauthorized("signed request is for another server");
    const signedHeaders = /SignedHeaders=([^,]+)/.exec(headers.authorization ?? "")?.[1]?.split(";") ?? [];
    if (!signedHeaders.includes("x-weft-server-id") || !signedHeaders.includes("host")) {
      throw unauthorized("x-weft-server-id must be signed");
    }
    return { method: "POST", url: r.url, headers, body: STS_BODY };
  }

  private async callSts(r: SignedRequest): Promise<string> {
    const { host: _host, ...headers } = r.headers;
    let res: Response;
    try {
      res = await this.doFetch(r.url, {
        method: "POST",
        headers,
        body: r.body,
        redirect: "error",
        signal: AbortSignal.timeout(5000),
      });
    } catch (e) {
      throw unauthorized(`could not verify credentials with STS: ${e instanceof Error ? e.message : String(e)}`);
    }
    const text = await res.text();
    if (!res.ok) throw unauthorized("STS rejected the signed request");
    const arn = /<Arn>([^<]+)<\/Arn>/.exec(text)?.[1];
    if (!arn) throw unauthorized("STS response had no ARN");
    return arn;
  }

  identityFromArn(arn: string): InternalIdentity {
    // arn:aws:sts::<account>:assumed-role/<role>/<session>
    const m = /^arn:aws[a-z-]*:sts::(\d{12}):assumed-role\/([^/]+)\/(.+)$/.exec(arn);
    if (!m) throw forbidden("caller is not an assumed IAM role");
    const [, account, role, session] = m as unknown as [string, string, string, string];
    if (this.cfg.accountId && account !== this.cfg.accountId) throw forbidden("caller is in another AWS account");
    if (role === this.cfg.hostRoleName) {
      if (!/^i-[0-9a-f]{8,17}$/.test(session)) throw forbidden("host role session is not an EC2 instance");
      return { kind: "host", hostId: session };
    }
    if (role === this.cfg.gatewayRoleName) return { kind: "gateway" };
    throw forbidden(`role ${role} may not call internal APIs`);
  }
}
