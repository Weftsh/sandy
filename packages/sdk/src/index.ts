/**
 * Weft Sandboxes helpers.
 *
 * Sandboxes run through the unmodified E2B SDK (`e2b` on npm and PyPI).
 * Point it at your stack with three environment variables, or call
 * {@link configureE2B} before creating sandboxes.
 */
export * from "./admin.js";

export interface StackConnection {
  /** `https://api.<domain>`; the stack's `ApiUrl` output. */
  apiUrl: string;
  /** The stack's `Domain` output. */
  domain: string;
  /** A team API key. */
  apiKey: string;
}

/** The environment variables the E2B SDKs read. */
export function e2bEnvironment(c: StackConnection): Record<string, string> {
  if (!/^https?:\/\//.test(c.apiUrl)) throw new Error("apiUrl must start with https:// (or http:// in development)");
  if (!c.domain || c.domain.includes("/")) throw new Error("domain must be a host name, e.g. sandbox.example.com");
  return { E2B_API_URL: c.apiUrl.replace(/\/+$/, ""), E2B_DOMAIN: c.domain, E2B_API_KEY: c.apiKey };
}

/**
 * Sets E2B_API_URL, E2B_DOMAIN and E2B_API_KEY for this process, so the E2B
 * SDK talks to your Weft Sandboxes stack.
 */
export function configureE2B(c: StackConnection): void {
  Object.assign(process.env, e2bEnvironment(c));
}
