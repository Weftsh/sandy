/**
 * API keys. The E2B SDKs send `X-API-KEY`; admin tooling may also use
 * `Authorization: Bearer`. Keys are stored as SHA-256 hashes.
 */
import { hashKey, newApiKey, randomId } from "../ids.js";
import { forbidden, unauthorized } from "../errors.js";
import type { ApiKey, Store } from "../store/types.js";

export interface Principal {
  teamId: string;
  role: "team" | "admin";
  keyId: string;
}

export const ADMIN_TEAM_ID = "team_admin";
const BOOTSTRAP_ADMIN_KEY_ID = "key_bootstrap_admin";

export function presentedKey(headers: Record<string, string | string[] | undefined>): string | undefined {
  const x = headers["x-api-key"];
  if (typeof x === "string" && x.length > 0) return x.trim();
  const auth = headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return undefined;
}

export class ApiKeys {
  private cache = new Map<string, { principal: Principal | null; at: number }>();

  constructor(private store: Store) {}

  async authenticate(headers: Record<string, string | string[] | undefined>): Promise<Principal> {
    const key = presentedKey(headers);
    if (!key || key.length > 512) throw unauthorized();
    const hash = hashKey(key);
    const cached = this.cache.get(hash);
    // Short cache so a revoked key stops working within seconds.
    if (cached && Date.now() - cached.at < 5000) {
      if (!cached.principal) throw unauthorized();
      return cached.principal;
    }
    const record = await this.store.getApiKeyByHash(hash);
    const principal = record ? { teamId: record.teamId, role: record.role, keyId: record.keyId } : null;
    if (this.cache.size > 10_000) this.cache.clear();
    this.cache.set(hash, { principal, at: Date.now() });
    if (!principal) throw unauthorized();
    return principal;
  }

  async requireAdmin(headers: Record<string, string | string[] | undefined>): Promise<Principal> {
    const p = await this.authenticate(headers);
    if (p.role !== "admin") throw forbidden("this operation needs an admin key");
    return p;
  }

  /** Creates a key and returns its plaintext; only the hash is stored. */
  async create(teamId: string, role: "team" | "admin", name: string): Promise<{ key: string; record: ApiKey }> {
    const key = newApiKey();
    const record: ApiKey = {
      keyHash: hashKey(key),
      keyId: `key_${randomId(16)}`,
      teamId,
      role,
      name,
      prefix: key.slice(0, 12),
      createdAt: new Date().toISOString(),
    };
    await this.store.putApiKey(record);
    return { key, record };
  }

  /** Makes sure a configured bootstrap admin key exists. */
  /**
   * Makes the stack's bootstrap admin key valid and revokes any previous
   * bootstrap key, so rotating the secret and restarting retires the old one.
   */
  async ensureAdminKey(plaintext: string): Promise<void> {
    const hash = hashKey(plaintext);
    for (const old of await this.store.listApiKeys(ADMIN_TEAM_ID)) {
      if (old.keyId === BOOTSTRAP_ADMIN_KEY_ID && old.keyHash !== hash) {
        await this.store.deleteApiKey(old.keyHash);
        this.cache.delete(old.keyHash);
      }
    }
    if (await this.store.getApiKeyByHash(hash)) return;
    await this.store.putApiKey({
      keyHash: hash,
      keyId: BOOTSTRAP_ADMIN_KEY_ID,
      teamId: ADMIN_TEAM_ID,
      role: "admin",
      name: "bootstrap admin key",
      prefix: plaintext.slice(0, 12),
      createdAt: new Date().toISOString(),
    });
  }

  async revoke(teamId: string, keyId: string): Promise<boolean> {
    const keys = await this.store.listApiKeys(teamId);
    const k = keys.find((x) => x.keyId === keyId);
    if (!k) return false;
    await this.store.deleteApiKey(k.keyHash);
    this.cache.delete(k.keyHash);
    return true;
  }
}
