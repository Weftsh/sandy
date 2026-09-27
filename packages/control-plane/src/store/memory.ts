/**
 * In-memory store for development and tests. Values are deep-copied on the
 * way in and out so callers cannot mutate stored state by accident.
 */
import { VersionConflict, type ApiKey, type BuildRecord, type Host, type Sandbox, type Store, type Team, type Template } from "./types.js";

const clone = <T>(v: T): T => structuredClone(v);

export class MemoryStore implements Store {
  private teams = new Map<string, Team>();
  private keys = new Map<string, ApiKey>();
  private templates = new Map<string, Template>();
  private builds = new Map<string, BuildRecord>();
  private sandboxes = new Map<string, Sandbox>();
  private hosts = new Map<string, Host>();
  private meta = new Map<string, unknown>();

  async putTeam(t: Team) {
    this.teams.set(t.teamId, clone(t));
  }
  async getTeam(id: string) {
    const t = this.teams.get(id);
    return t && clone(t);
  }
  async listTeams() {
    return [...this.teams.values()].map(clone);
  }

  async putApiKey(k: ApiKey) {
    this.keys.set(k.keyHash, clone(k));
  }
  async getApiKeyByHash(hash: string) {
    const k = this.keys.get(hash);
    return k && clone(k);
  }
  async listApiKeys(teamId: string) {
    return [...this.keys.values()].filter((k) => k.teamId === teamId).map(clone);
  }
  async deleteApiKey(hash: string) {
    this.keys.delete(hash);
  }

  async putTemplate(t: Template) {
    this.templates.set(t.templateId, clone(t));
  }
  async getTemplate(id: string) {
    const t = this.templates.get(id);
    return t && clone(t);
  }
  async listTemplatesVisibleTo(teamId: string) {
    return [...this.templates.values()].filter((t) => t.teamId === null || t.teamId === teamId).map(clone);
  }
  async listAllTemplates() {
    return [...this.templates.values()].map(clone);
  }
  async deleteTemplate(id: string) {
    this.templates.delete(id);
  }

  async putBuild(b: BuildRecord) {
    this.builds.set(b.buildId, clone(b));
  }
  async getBuild(id: string) {
    const b = this.builds.get(id);
    return b && clone(b);
  }

  async createSandbox(s: Sandbox) {
    if (this.sandboxes.has(s.sandboxId)) throw new VersionConflict(s.sandboxId);
    this.sandboxes.set(s.sandboxId, clone(s));
  }
  async updateSandbox(s: Sandbox) {
    const current = this.sandboxes.get(s.sandboxId);
    if (!current || current.version !== s.version - 1) throw new VersionConflict(s.sandboxId);
    this.sandboxes.set(s.sandboxId, clone(s));
  }
  async getSandbox(id: string) {
    const s = this.sandboxes.get(id);
    return s && clone(s);
  }
  async deleteSandbox(id: string) {
    this.sandboxes.delete(id);
  }
  async listSandboxesByTeam(teamId: string) {
    return [...this.sandboxes.values()].filter((s) => s.teamId === teamId).map(clone);
  }
  async listAllSandboxes() {
    return [...this.sandboxes.values()].map(clone);
  }

  async putHost(h: Host) {
    this.hosts.set(h.hostId, clone(h));
  }
  async getHost(id: string) {
    const h = this.hosts.get(id);
    return h && clone(h);
  }
  async listHosts() {
    return [...this.hosts.values()].map(clone);
  }
  async deleteHost(id: string) {
    this.hosts.delete(id);
  }

  async getMeta<T>(key: string) {
    const v = this.meta.get(key);
    return v === undefined ? undefined : (clone(v) as T);
  }
  async putMeta<T>(key: string, value: T) {
    this.meta.set(key, clone(value));
  }
}
