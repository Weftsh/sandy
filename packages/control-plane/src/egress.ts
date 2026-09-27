/**
 * Egress policy: the TypeScript side of `crates/netpolicy`.
 *
 * Admins set a policy per team (deny-all by default). The E2B SDK's
 * `allow_internet_access` and `network` options can only narrow that policy
 * for one sandbox, never widen it: the SDK defaults to "internet on", and a
 * sandbox must not get more access than its team was given.
 *
 * The host agent and egress gateway compile and enforce the policy; this
 * module validates it early and computes the per-sandbox policy.
 */
import { isIP } from "node:net";

import { ApiError, badRequest } from "./errors.js";

export interface AllowRule {
  host: string;
  ports?: number[];
}

export interface CredentialRule {
  host: string;
  header: string;
  secretId: string;
  secretKey?: string;
  format?: string;
}

export interface EgressPolicy {
  allow: AllowRule[];
  credentials: CredentialRule[];
}

export const DENY_ALL: EgressPolicy = Object.freeze({ allow: [], credentials: [] }) as EgressPolicy;
export const MAX_RULES = 256;

type Pattern =
  | { kind: "exact"; host: string }
  | { kind: "subdomains"; domain: string }
  | { kind: "any" }
  | { kind: "cidr"; family: 4 | 6; bits: bigint; prefix: number };

const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

export function normalizeHostname(name: string): string | null {
  let n = name.trim().toLowerCase();
  if (n.endsWith(".")) n = n.slice(0, -1);
  if (!n || n.length > 253 || isIP(n)) return null;
  // Resolvers read names like 127.1 or 2130706433 as IPv4 addresses.
  if (/^\d+$/.test(n.slice(n.lastIndexOf(".") + 1))) return null;
  return n.split(".").every((l) => LABEL.test(l)) ? n : null;
}

function ipToBigInt(ip: string): { family: 4 | 6; value: bigint } | null {
  const fam = isIP(ip);
  if (fam === 4) {
    const parts = ip.split(".").map(Number);
    return { family: 4, value: parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n) };
  }
  if (fam === 6) {
    const [head = "", tail = ""] = ip.split("::");
    const h = head ? head.split(":") : [];
    const t = ip.includes("::") ? (tail ? tail.split(":") : []) : [];
    const groups = ip.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
    if (groups.length !== 8 || groups.some((g) => g.includes("."))) return null;
    return { family: 6, value: groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n) };
  }
  return null;
}

export function parsePattern(raw: string): Pattern | string {
  const p = raw.trim();
  if (p === "*") return { kind: "any" };
  const slash = p.indexOf("/");
  const ipPart = slash >= 0 ? p.slice(0, slash) : p;
  const ip = ipToBigInt(ipPart);
  if (ip) {
    const width = ip.family === 4 ? 32 : 128;
    const prefix = slash >= 0 ? Number(p.slice(slash + 1)) : width;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > width) return "invalid CIDR prefix";
    const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(width - prefix);
    return { kind: "cidr", family: ip.family, bits: ip.value & mask, prefix };
  }
  if (p.startsWith("*.")) {
    const domain = normalizeHostname(p.slice(2));
    if (!domain) return "not a valid domain name";
    if (!domain.includes(".")) return "wildcards must cover a registrable domain, not a top-level domain";
    return { kind: "subdomains", domain };
  }
  if (p.includes("*")) return "only a leading `*.` wildcard is supported";
  const host = normalizeHostname(p);
  return host ? { kind: "exact", host } : "not a valid hostname";
}

const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FRAMING_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "proxy-authorization",
  "proxy-connection",
]);

/** Validates a policy document from an admin; throws a 400 describing the first problem. */
export function validatePolicy(raw: unknown): EgressPolicy {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw badRequest("policy must be an object");
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (k !== "allow" && k !== "credentials") throw badRequest(`unknown policy field ${k}`);
  }
  const allow = obj.allow ?? [];
  const credentials = obj.credentials ?? [];
  if (!Array.isArray(allow) || !Array.isArray(credentials)) throw badRequest("allow and credentials must be arrays");
  if (allow.length + credentials.length > MAX_RULES) throw badRequest(`a policy may have at most ${MAX_RULES} rules`);
  const out: EgressPolicy = { allow: [], credentials: [] };
  allow.forEach((r: unknown, i) => {
    const rule = r as Record<string, unknown>;
    if (typeof rule !== "object" || rule === null || typeof rule.host !== "string") throw badRequest(`allow[${i}].host is required`);
    for (const k of Object.keys(rule)) if (k !== "host" && k !== "ports") throw badRequest(`allow[${i}]: unknown field ${k}`);
    const parsed = parsePattern(rule.host);
    if (typeof parsed === "string") throw badRequest(`allow[${i}]: ${parsed}`);
    let ports: number[] | undefined;
    if (rule.ports !== undefined) {
      if (!Array.isArray(rule.ports) || !rule.ports.every((p) => Number.isInteger(p) && p >= 1 && p <= 65535)) {
        throw badRequest(`allow[${i}].ports must be a list of ports 1-65535`);
      }
      ports = rule.ports as number[];
    }
    out.allow.push(ports ? { host: rule.host, ports } : { host: rule.host });
  });
  credentials.forEach((c: unknown, i) => {
    const cred = c as Record<string, unknown>;
    if (typeof cred !== "object" || cred === null) throw badRequest(`credentials[${i}] must be an object`);
    for (const k of Object.keys(cred)) {
      if (!["host", "header", "secretId", "secretKey", "format"].includes(k)) throw badRequest(`credentials[${i}]: unknown field ${k}`);
    }
    if (typeof cred.host !== "string" || !normalizeHostname(cred.host)) throw badRequest(`credentials[${i}].host must be an exact hostname`);
    if (typeof cred.header !== "string" || !HEADER_NAME.test(cred.header)) throw badRequest(`credentials[${i}].header is not a valid header name`);
    if (FRAMING_HEADERS.has(cred.header.toLowerCase())) throw badRequest(`credentials[${i}].header cannot carry a credential`);
    if (typeof cred.secretId !== "string" || !cred.secretId.trim()) throw badRequest(`credentials[${i}].secretId is required`);
    if (cred.secretKey !== undefined && typeof cred.secretKey !== "string") throw badRequest(`credentials[${i}].secretKey must be a string`);
    if (cred.format !== undefined) {
      if (typeof cred.format !== "string" || !cred.format.includes("{{secret}}")) throw badRequest(`credentials[${i}].format must contain {{secret}}`);
      if (/[\r\n]/.test(cred.format)) throw badRequest(`credentials[${i}].format must not contain line breaks`);
    }
    if (out.credentials.some((c) => normalizeHostname(c.host) === normalizeHostname(cred.host as string))) {
      throw badRequest(`credentials[${i}]: another credential rule already covers this host`);
    }
    const rule: CredentialRule = { host: cred.host, header: cred.header, secretId: cred.secretId };
    if (cred.secretKey !== undefined) rule.secretKey = cred.secretKey as string;
    if (cred.format !== undefined) rule.format = cred.format as string;
    out.credentials.push(rule);
  });
  return out;
}

/** Whether pattern `outer` covers everything pattern `inner` matches. */
function covers(outer: Pattern, inner: Pattern): boolean {
  switch (outer.kind) {
    case "any":
      // `*` means any *public* destination; it never covers a private range,
      // because a CIDR rule would open it.
      return inner.kind !== "cidr" || (inner.family === 4 && inner.prefix === 32 && isPublicV4(inner.bits));
    case "exact":
      return inner.kind === "exact" && inner.host === outer.host;
    case "subdomains":
      return (
        (inner.kind === "exact" && inner.host.endsWith(`.${outer.domain}`)) ||
        (inner.kind === "subdomains" && (inner.domain === outer.domain || inner.domain.endsWith(`.${outer.domain}`)))
      );
    case "cidr": {
      if (inner.kind !== "cidr" || inner.family !== outer.family || inner.prefix < outer.prefix) return false;
      const width = outer.family === 4 ? 32 : 128;
      const mask = outer.prefix === 0 ? 0n : ((1n << BigInt(outer.prefix)) - 1n) << BigInt(width - outer.prefix);
      return (inner.bits & mask) === outer.bits;
    }
  }
}

function portsCovered(outer: AllowRule, inner: number[] | undefined): boolean {
  const outerPorts = outer.ports ?? [80, 443];
  return (inner ?? [80, 443]).every((p) => outerPorts.includes(p));
}

/** Mirrors `IpClass::Public` for IPv4 in `crates/netpolicy/src/ip.rs`. */
export function isPublicV4(value: bigint): boolean {
  const o = [24n, 16n, 8n, 0n].map((s) => Number((value >> s) & 255n)) as [number, number, number, number];
  const [a, b, c] = o;
  const forbiddenOrPrivate =
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    (a === 198 && (b === 18 || b === 19));
  return !forbiddenOrPrivate;
}

/** The E2B network options this service understands. */
export interface SdkNetworkOptions {
  allowInternetAccess?: boolean | null;
  network?: Record<string, unknown> | null;
}

/**
 * Computes a sandbox's policy from its team's policy and the SDK options.
 * Throws a 400 for options that would widen access or are not supported.
 */
export function sandboxPolicy(team: EgressPolicy, opts: SdkNetworkOptions): EgressPolicy {
  const net = opts.network ?? {};
  for (const unsupported of ["rules", "egressProxy", "maskRequestHost"]) {
    if (net[unsupported] !== undefined && net[unsupported] !== null) {
      throw badRequest(
        `network.${unsupported} is not supported; configure egress rules and credentials through your team's egress policy`,
      );
    }
  }
  const denyOut = net.denyOut;
  if (denyOut !== undefined && denyOut !== null) {
    if (!Array.isArray(denyOut) || denyOut.some((d) => typeof d !== "string")) throw badRequest("network.denyOut must be a list");
    const unsupported = (denyOut as string[]).filter((d) => d !== "0.0.0.0/0" && d !== "::/0");
    if (unsupported.length > 0) {
      throw badRequest(
        `network.denyOut supports only "0.0.0.0/0"; sandboxes are deny-by-default and get only what their team's policy allows`,
      );
    }
  }
  const denyAll = opts.allowInternetAccess === false || (Array.isArray(denyOut) && denyOut.length > 0);
  if (!denyAll) return team;

  const allowOut = net.allowOut;
  if (allowOut === undefined || allowOut === null) return DENY_ALL;
  if (!Array.isArray(allowOut) || allowOut.some((a) => typeof a !== "string")) throw badRequest("network.allowOut must be a list of strings");
  const teamPatterns = team.allow.map((r) => ({ rule: r, pattern: parsePattern(r.host) }));
  const credentialHosts = team.credentials.map((c) => normalizeHostname(c.host));
  const narrowed: EgressPolicy = { allow: [], credentials: [] };
  for (const entry of allowOut as string[]) {
    const pattern = parsePattern(entry);
    if (typeof pattern === "string") throw badRequest(`network.allowOut entry ${JSON.stringify(entry)}: ${pattern}`);
    const covered =
      teamPatterns.some(({ rule, pattern: tp }) => typeof tp !== "string" && covers(tp, pattern) && portsCovered(rule, undefined)) ||
      (pattern.kind === "exact" && credentialHosts.includes(pattern.host));
    if (!covered) {
      throw new ApiError(
        403,
        `network.allowOut entry ${JSON.stringify(entry)} is not permitted by your team's egress policy`,
      );
    }
    narrowed.allow.push({ host: entry });
  }
  narrowed.credentials = team.credentials.filter((c) =>
    narrowed.allow.some((a) => {
      const p = parsePattern(a.host);
      const h = normalizeHostname(c.host);
      return typeof p !== "string" && h !== null && covers(p, { kind: "exact", host: h });
    }),
  );
  return narrowed;
}
