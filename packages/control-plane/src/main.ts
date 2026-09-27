#!/usr/bin/env node
/**
 * Weft Sandboxes control plane.
 *
 * One binary, three roles (WEFT_ROLES): `api` (E2B-compatible REST, admin and
 * internal APIs), `edge` (sandbox traffic proxy) and `worker` (timeouts,
 * reconciliation, template bootstrap, license check, metrics). Production
 * runs each role as its own ECS service; development runs all three in one
 * process.
 */
import { CloudWatchClient, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { ECRClient, GetAuthorizationTokenCommand } from "@aws-sdk/client-ecr";
import { S3Client } from "@aws-sdk/client-s3";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

import { ArtifactStore } from "./artifacts.js";
import { ADMIN_TEAM_ID, ApiKeys } from "./auth/apikeys.js";
import { InternalAuth } from "./auth/internal.js";
import { buildApi } from "./api/server.js";
import { loadConfig, type Config } from "./config.js";
import { Edge, createEdgeServer } from "./edge/proxy.js";
import { HostRegistry, hostUtilization } from "./hosts/registry.js";
import { LicenseService } from "./license/service.js";
import { jsonLogger, type Logger } from "./log.js";
import { SandboxService } from "./sandboxes/service.js";
import { DynamoStore } from "./store/dynamodb.js";
import { MemoryStore } from "./store/memory.js";
import type { Store } from "./store/types.js";
import { TemplateService, type RegistryCredentials } from "./templates/service.js";

export interface App {
  config: Config;
  store: Store;
  keys: ApiKeys;
  hosts: HostRegistry;
  templates: TemplateService;
  sandboxes: SandboxService;
  license: LicenseService;
  internalAuth: InternalAuth;
  log: Logger;
}

function ecrCredentials(config: Config): RegistryCredentials | undefined {
  if (!config.ecrRegistry) return undefined;
  const ecr = new ECRClient({ region: config.region });
  return {
    async forImage(image: string) {
      if (!image.startsWith(`${config.ecrRegistry}/`)) return undefined;
      const out = await ecr.send(new GetAuthorizationTokenCommand({}));
      const token = out.authorizationData?.[0]?.authorizationToken;
      if (!token) return undefined;
      const [username, password] = Buffer.from(token, "base64").toString("utf8").split(":");
      return username && password ? { username, password } : undefined;
    },
  };
}

export async function createApp(config: Config, store?: Store, log: Logger = jsonLogger("control-plane")): Promise<App> {
  const db =
    store ??
    (config.store.kind === "memory"
      ? new MemoryStore()
      : new DynamoStore(config.store.tablePrefix, new DynamoDBClient({ region: config.region, endpoint: config.store.endpoint })));
  const keys = new ApiKeys(db);
  const hosts = new HostRegistry(db);
  const artifacts = config.artifactsBucket ? new ArtifactStore(new S3Client({ region: config.region }), config.artifactsBucket) : undefined;
  const templates = new TemplateService(db, hosts, artifacts, ecrCredentials(config), {
    vcpus: config.defaults.vcpus,
    memoryMib: config.defaults.memoryMib,
    diskMib: config.defaults.diskMib,
  }, log);
  let accountId = config.internalAuth.kind === "aws-iam" ? config.internalAuth.accountId : undefined;
  const lookupAccount = async () => {
    if (accountId || config.devMode) return accountId;
    const out = await new STSClient({ region: config.region }).send(new GetCallerIdentityCommand({}));
    accountId = out.Account;
    return accountId;
  };
  const license = new LicenseService(
    db,
    {
      version: config.version,
      region: config.region,
      configuredKey: config.license.key,
      mode: config.license.mode,
      marketplace: config.license.marketplace,
      endpoint: config.license.endpoint,
      extraPublicKeys: config.license.devPublicKeys,
      accountId: lookupAccount,
    },
    log,
  );
  const sandboxes = new SandboxService(
    db,
    hosts,
    templates,
    artifacts,
    license,
    {
      domain: config.domain,
      defaultTimeoutSec: config.defaults.timeoutSec,
      maxTimeoutSec: config.defaults.maxTimeoutSec,
      pausedRetentionDays: config.pausedRetentionDays,
      egressCaCert: config.egressCaCert,
    },
    log,
  );
  const ia = config.internalAuth;
  const internalAuth = new InternalAuth(
    ia.kind === "dev-token"
      ? { kind: "dev-token", devToken: ia.token }
      : {
          kind: "aws-iam",
          serverId: ia.serverId,
          region: config.region,
          accountId: await lookupAccount().catch(() => undefined),
          hostRoleName: ia.hostRoleName,
          gatewayRoleName: ia.gatewayRoleName,
        },
  );
  // The edge only proxies traffic; it neither needs nor may write licensing
  // state (its IAM role can read one meta item).
  if (config.roles.has("api") || config.roles.has("worker")) {
    if (config.bootstrapAdminKey) await keys.ensureAdminKey(config.bootstrapAdminKey);
    await license.init();
  }
  return { config, store: db, keys, hosts, templates, sandboxes, license, internalAuth, log };
}

/** Periodic work. Runs in exactly one process (the worker service). */
export function startWorker(app: App): () => void {
  const timers: NodeJS.Timeout[] = [];
  const every = (ms: number, name: string, fn: () => Promise<void>) => {
    let running = false;
    const tick = async () => {
      if (running) return;
      running = true;
      try {
        await fn();
      } catch (e) {
        app.log.warn("worker task failed", { task: name, error: String(e) });
      } finally {
        running = false;
      }
    };
    timers.push(setInterval(() => void tick(), ms));
    void tick();
  };
  const admin = { teamId: ADMIN_TEAM_ID, role: "admin" as const, keyId: "worker" };
  every(2_000, "reap", () => app.sandboxes.reap());
  every(30_000, "sweep-dead-hosts", () => app.sandboxes.sweepDeadHosts());
  every(10_000, "bootstrap-templates", () => app.templates.ensureBootstrapTemplates(app.config.bootstrapTemplates, admin));
  every(60_000, "resume-builds", () => app.templates.resumeFollowing());
  every(600_000, "evict-builds", () => app.sandboxes.evictStaleBuilds());
  // Daily license check, spread over the day by a random offset.
  const offset = Math.floor(Math.random() * 3_600_000);
  timers.push(setTimeout(() => every(86_400_000, "license-check", () => app.license.runCheck()), offset));
  // License usage (peak concurrency) is tracked whether or not metrics are
  // published.
  every(60_000, "usage", async () => {
    const running = (await app.store.listAllSandboxes()).filter((s) => s.state === "running").length;
    await app.license.recordConcurrency(running);
  });
  if (app.config.metricsNamespace) {
    const cw = new CloudWatchClient({ region: app.config.region });
    every(60_000, "metrics", async () => {
      const hosts = await app.hosts.liveHosts();
      // Capacity-weighted mean of each host's utilization (the tighter of its
      // slots and its memory), so memory-bound hosts also trigger scale-out.
      const capacity = hosts.reduce((n, h) => n + h.capacity.maxSandboxes, 0);
      const used = hosts.reduce((n, h) => n + hostUtilization(h) * h.capacity.maxSandboxes, 0);
      const running = (await app.store.listAllSandboxes()).filter((s) => s.state === "running").length;
      await cw.send(
        new PutMetricDataCommand({
          Namespace: app.config.metricsNamespace,
          MetricData: [
            { MetricName: "SlotUtilization", Unit: "Percent", Value: capacity === 0 ? 100 : (100 * used) / capacity, Dimensions: [{ Name: "StackName", Value: app.config.metricsNamespace! }] },
            { MetricName: "RunningSandboxes", Unit: "Count", Value: running, Dimensions: [{ Name: "StackName", Value: app.config.metricsNamespace! }] },
            { MetricName: "LiveHosts", Unit: "Count", Value: hosts.length, Dimensions: [{ Name: "StackName", Value: app.config.metricsNamespace! }] },
          ],
        }),
      );
    });
  }
  return () => timers.forEach((t) => clearInterval(t));
}

async function main(): Promise<void> {
  const config = loadConfig();
  const log = jsonLogger("control-plane");
  const app = await createApp(config, undefined, log);
  const closers: (() => Promise<void> | void)[] = [];

  if (config.roles.has("api")) {
    const api = buildApi({ ...app, auth: app.internalAuth, version: config.version });
    await api.listen({ host: config.apiListen.host, port: config.apiListen.port });
    void app.templates.resumeFollowing();
    closers.push(() => api.close());
    log.info("api listening", { ...config.apiListen });
  }
  if (config.roles.has("edge")) {
    const edge = createEdgeServer(new Edge({ store: app.store, hosts: app.hosts, domain: config.domain, log }), config.edgeTls);
    await new Promise<void>((resolve) => edge.listen(config.edgeListen.port, config.edgeListen.host, resolve));
    closers.push(() => new Promise<void>((r) => edge.close(() => r())));
    log.info("edge listening", { ...config.edgeListen, tls: !!config.edgeTls });
  }
  if (config.roles.has("worker")) {
    closers.push(startWorker(app));
    log.info("worker started");
  }
  if (config.devMode) log.warn("development mode: in-memory state and development-only settings are enabled");

  const shutdown = async (signal: string) => {
    log.info("shutting down", { signal });
    await Promise.allSettled(closers.map((c) => c()));
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

const isEntrypoint = import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("/main.js");
if (isEntrypoint) {
  main().catch((e: unknown) => {
    process.stderr.write(`weft-control-plane: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
    process.exit(1);
  });
}
