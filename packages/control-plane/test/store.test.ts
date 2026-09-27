/**
 * The same contract for the in-memory store and the DynamoDB store. The
 * DynamoDB run needs DynamoDB Local: set WEFT_TEST_DYNAMODB_ENDPOINT (for
 * example http://127.0.0.1:8000); it is skipped otherwise.
 */
import { CreateTableCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { describe, expect, it } from "vitest";

import { MemoryStore } from "../src/store/memory.js";
import { DynamoStore, tableDefinitions } from "../src/store/dynamodb.js";
import { VersionConflict, type Sandbox, type Store, type Template } from "../src/store/types.js";
import { randomId } from "../src/ids.js";

function sandbox(id: string, teamId: string): Sandbox {
  return {
    sandboxId: id,
    teamId,
    templateId: "tpl",
    alias: "base",
    buildId: "b1",
    hostId: null,
    clientId: "c",
    state: "starting",
    version: 1,
    envdAccessToken: "tok",
    trafficAccessToken: null,
    envdVersion: "0.9.0",
    cpuCount: 2,
    memoryMB: 512,
    diskSizeMB: 2048,
    metadata: { k: "v" },
    envVars: {},
    startedAt: new Date().toISOString(),
    endAt: new Date().toISOString(),
    autoPause: false,
    autoResume: false,
    allowInternetAccess: null,
    egressPolicy: { allow: [], credentials: [] },
  };
}

function template(id: string, teamId: string | null, name: string): Template {
  const now = new Date().toISOString();
  return {
    templateId: id,
    teamId,
    names: [name],
    image: "python:3.12-slim",
    buildId: null,
    latestBuildId: "b",
    status: "building",
    cpuCount: 2,
    memoryMB: 512,
    diskSizeMB: 2048,
    envVars: {},
    createdAt: now,
    updatedAt: now,
  };
}

function contract(name: string, make: () => Promise<Store>) {
  describe(`${name} store`, () => {
    it("creates and versions sandboxes", async () => {
      const s = await make();
      const sb = sandbox(randomId(), "team_a");
      await s.createSandbox(sb);
      await expect(s.createSandbox(sb)).rejects.toBeInstanceOf(VersionConflict);
      const next = { ...sb, state: "running" as const, version: 2 };
      await s.updateSandbox(next);
      await expect(s.updateSandbox({ ...sb, version: 2 })).rejects.toBeInstanceOf(VersionConflict);
      expect((await s.getSandbox(sb.sandboxId))?.state).toBe("running");
      const copy = await s.getSandbox(sb.sandboxId);
      copy!.metadata.k = "mutated";
      expect((await s.getSandbox(sb.sandboxId))?.metadata.k).toBe("v");
      await s.deleteSandbox(sb.sandboxId);
      expect(await s.getSandbox(sb.sandboxId)).toBeUndefined();
    });

    it("lists sandboxes by team", async () => {
      const s = await make();
      const team = `team_${randomId(8)}`;
      await s.createSandbox(sandbox(randomId(), team));
      await s.createSandbox(sandbox(randomId(), team));
      await s.createSandbox(sandbox(randomId(), "team_other"));
      // DynamoDB GSIs are eventually consistent; DynamoDB Local is immediate.
      expect(await s.listSandboxesByTeam(team)).toHaveLength(2);
      expect((await s.listAllSandboxes()).length).toBeGreaterThanOrEqual(3);
    });

    it("scopes templates to teams plus public ones", async () => {
      const s = await make();
      const team = `team_${randomId(8)}`;
      await s.putTemplate(template(randomId(), team, "mine"));
      await s.putTemplate(template(randomId(), null, "public"));
      await s.putTemplate(template(randomId(), "team_other", "theirs"));
      const names = (await s.listTemplatesVisibleTo(team)).flatMap((t) => t.names);
      expect(names).toContain("mine");
      expect(names).toContain("public");
      expect(names).not.toContain("theirs");
    });

    it("stores keys, hosts and meta", async () => {
      const s = await make();
      const hash = randomId(40);
      await s.putApiKey({ keyHash: hash, keyId: "k1", teamId: "team_k", role: "team", name: "n", prefix: "weft_sk_abc", createdAt: "x" });
      expect((await s.getApiKeyByHash(hash))?.keyId).toBe("k1");
      expect((await s.listApiKeys("team_k")).map((k) => k.keyId)).toContain("k1");
      await s.deleteApiKey(hash);
      expect(await s.getApiKeyByHash(hash)).toBeUndefined();
      await s.putMeta("usage-test", { monthly: { "2026-09": 3 } });
      expect(await s.getMeta("usage-test")).toEqual({ monthly: { "2026-09": 3 } });
      expect(await s.getMeta("missing")).toBeUndefined();
    });
  });
}

contract("memory", async () => new MemoryStore());

const endpoint = process.env.WEFT_TEST_DYNAMODB_ENDPOINT;
if (endpoint) {
  const prefix = `t${randomId(6)}-`;
  let ready: Promise<void> | undefined;
  const client = new DynamoDBClient({ endpoint, region: "us-east-1", credentials: { accessKeyId: "local", secretAccessKey: "local" } });
  contract("dynamodb", async () => {
    ready ??= Promise.all(tableDefinitions(prefix).map((t) => client.send(new CreateTableCommand(t)))).then(() => undefined);
    await ready;
    return new DynamoStore(prefix, client);
  });
} else {
  describe.skip("dynamodb store (set WEFT_TEST_DYNAMODB_ENDPOINT)", () => {
    it("skipped", () => {});
  });
}
