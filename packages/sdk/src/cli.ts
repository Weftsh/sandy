#!/usr/bin/env node
/**
 * weft-sandbox: administer a Weft Sandboxes stack.
 *
 * Sandboxes are created with the E2B SDK; this CLI manages what surrounds
 * them. Run `weft-sandbox help` for the commands.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { WeftAdmin, type EgressPolicy, type TemplateInfo } from "./admin.js";
import { e2bEnvironment } from "./index.js";

interface CliConfig {
  apiUrl?: string;
  apiKey?: string;
  domain?: string;
}

const CONFIG_PATH = process.env.WEFT_SANDBOX_CONFIG ?? join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "weft-sandbox", "config.json");

const HELP = `weft-sandbox: administer a Weft Sandboxes stack

Setup
  login --api-url <url> --key <admin-key> [--domain <domain>]
  env --key <team-key>                 print E2B_* variables for the E2B SDK

License
  license status
  license install <license-key>

Teams, keys and egress
  teams list
  teams create <name>                  prints the team's first API key once
  keys list <team-id>
  keys create <team-id> [--name <name>]
  keys revoke <team-id> <key-id>
  egress get <team-id>
  egress set <team-id> <policy.json>   deny-all unless the policy allows it

Templates
  templates list
  templates get <template-id>
  templates build --name <name> --image <image-ref> (--team <team-id> | --public) [options] [--wait]
  templates build --name <name> --dockerfile <path> --repository <ecr-uri> [--context <dir>] (--team <team-id> | --public) [options] [--wait]
      options: --cpu <n> --memory <MiB> --disk <MiB> --start-cmd <cmd> --ready-cmd <cmd> --env K=V
  templates rebuild <template-id> [--wait]   same image and settings, new build
  templates delete <template-id>

Fleet
  hosts
  sandboxes

Settings come from ${CONFIG_PATH}, overridden by
WEFT_API_URL / WEFT_API_KEY or --api-url / --key.
`;

function loadConfig(): CliConfig {
  if (!existsSync(CONFIG_PATH)) return {};
  return JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as CliConfig;
}

function saveConfig(c: CliConfig): void {
  mkdirSync(dirname(CONFIG_PATH), { recursive: true, mode: 0o700 });
  writeFileSync(CONFIG_PATH, `${JSON.stringify(c, null, 2)}\n`, { mode: 0o600 });
  chmodSync(CONFIG_PATH, 0o600);
}

function fail(message: string): never {
  process.stderr.write(`weft-sandbox: ${message}\n`);
  process.exit(1);
}

function print(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function templateLine(t: TemplateInfo): string {
  const owner = t.public ? "public" : (t.teamId ?? "team");
  return `${t.templateId}  ${t.names.join(",").padEnd(20)} ${t.status.padEnd(9)} ${owner.padEnd(21)} ${t.image}`;
}

function sh(cmd: string, args: string[], input?: string): string {
  const r = spawnSync(cmd, args, { input, encoding: "utf8", stdio: [input === undefined ? "inherit" : "pipe", "pipe", "inherit"] });
  if (r.error) fail(`${cmd}: ${r.error.message}`);
  if (r.status !== 0) fail(`${cmd} ${args[0]} failed with exit code ${r.status}`);
  return r.stdout;
}

/** Builds a Dockerfile, pushes it to ECR and returns the pushed image digest reference. */
function buildAndPush(dockerfile: string, context: string, repository: string, name: string): string {
  const registry = repository.split("/")[0]!;
  const region = /\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/.exec(registry)?.[1];
  if (!region) fail(`--repository must be an ECR repository URI, got ${repository}`);
  const tag = `${repository}:${name}-${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14)}`;
  process.stderr.write(`building ${tag}\n`);
  sh("docker", ["build", "--platform", "linux/amd64", "-f", dockerfile, "-t", tag, context]);
  const password = execFileSync("aws", ["ecr", "get-login-password", "--region", region], { encoding: "utf8" });
  sh("docker", ["login", "--username", "AWS", "--password-stdin", registry], password);
  sh("docker", ["push", tag]);
  const digest = sh("docker", ["inspect", "--format", "{{index .RepoDigests 0}}", tag]).trim();
  return digest || tag;
}

async function main(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      "api-url": { type: "string" },
      key: { type: "string" },
      domain: { type: "string" },
      name: { type: "string" },
      image: { type: "string" },
      dockerfile: { type: "string" },
      context: { type: "string" },
      repository: { type: "string" },
      team: { type: "string" },
      cpu: { type: "string" },
      memory: { type: "string" },
      disk: { type: "string" },
      "start-cmd": { type: "string" },
      "ready-cmd": { type: "string" },
      env: { type: "string", multiple: true },
      public: { type: "boolean" },
      wait: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  const [group, action, ...rest] = positionals;
  if (!group || group === "help" || values.help) {
    process.stdout.write(HELP);
    return;
  }

  const config = loadConfig();
  if (group === "login") {
    const apiUrl = values["api-url"];
    const apiKey = values.key;
    if (!apiUrl || !apiKey) fail("login needs --api-url and --key");
    const admin = new WeftAdmin({ apiUrl, apiKey });
    const status = await admin.license.status();
    saveConfig({ apiUrl, apiKey, domain: values.domain ?? config.domain });
    process.stdout.write(`logged in to ${apiUrl} (license: ${status.state}); settings saved to ${CONFIG_PATH}\n`);
    return;
  }

  const apiUrl = values["api-url"] ?? process.env.WEFT_API_URL ?? config.apiUrl;
  const apiKey = values.key ?? process.env.WEFT_API_KEY ?? config.apiKey;

  if (group === "env") {
    if (!apiUrl) fail("no API URL; run `weft-sandbox login` first");
    const domain = values.domain ?? config.domain ?? new URL(apiUrl).hostname.replace(/^api\./, "");
    if (!values.key) fail("env needs --key <team-key>");
    for (const [k, v] of Object.entries(e2bEnvironment({ apiUrl, domain, apiKey: values.key }))) {
      process.stdout.write(`export ${k}=${JSON.stringify(v)}\n`);
    }
    return;
  }

  if (!apiUrl || !apiKey) fail("not logged in; run `weft-sandbox login --api-url <url> --key <admin-key>`");
  const admin = new WeftAdmin({ apiUrl, apiKey });

  switch (`${group} ${action ?? ""}`.trim()) {
    case "license status":
      return print(await admin.license.status());
    case "license install":
      if (!rest[0]) fail("license install needs the key");
      return print(await admin.license.install(rest[0]));
    case "teams list":
      return print(await admin.teams.list());
    case "teams create": {
      if (!rest[0]) fail("teams create needs a name");
      const out = await admin.teams.create(rest[0]);
      print(out.team);
      process.stderr.write(`\nAPI key for ${out.team.name} (shown once, store it now):\n`);
      process.stdout.write(`${out.apiKey.key}\n`);
      return;
    }
    case "keys list":
      if (!rest[0]) fail("keys list needs a team ID");
      return print(await admin.apiKeys.list(rest[0]));
    case "keys create": {
      if (!rest[0]) fail("keys create needs a team ID");
      const out = await admin.apiKeys.create(rest[0], values.name ?? "cli");
      process.stderr.write(`key ${out.keyId} (shown once, store it now):\n`);
      process.stdout.write(`${out.key}\n`);
      return;
    }
    case "keys revoke":
      if (!rest[0] || !rest[1]) fail("keys revoke needs a team ID and a key ID");
      await admin.apiKeys.revoke(rest[0], rest[1]);
      process.stdout.write("revoked\n");
      return;
    case "egress get":
      if (!rest[0]) fail("egress get needs a team ID");
      return print((await admin.teams.get(rest[0])).egressPolicy);
    case "egress set": {
      if (!rest[0] || !rest[1]) fail("egress set needs a team ID and a policy file");
      let policy: EgressPolicy;
      try {
        policy = JSON.parse(readFileSync(resolve(rest[1]), "utf8")) as EgressPolicy;
      } catch (e) {
        fail(`cannot read the policy in ${rest[1]}: ${(e as Error).message}`);
      }
      return print((await admin.teams.setEgressPolicy(rest[0], policy)).egressPolicy);
    }
    case "templates list":
      for (const t of await admin.templates.list()) process.stdout.write(`${templateLine(t)}\n`);
      return;
    case "templates get":
      if (!rest[0]) fail("templates get needs a template ID");
      return print(await admin.templates.get(rest[0]));
    case "templates rebuild": {
      if (!rest[0]) fail("templates rebuild needs a template ID");
      const t = await admin.templates.rebuild(rest[0]);
      process.stdout.write(`${templateLine(t)}\n`);
      if (values.wait) {
        const ready = await admin.templates.waitUntilReady(t.templateId, { onLog: (l) => process.stderr.write(`  ${l}\n`) });
        process.stdout.write(`ready: ${templateLine(ready)}\n`);
      }
      return;
    }
    case "templates delete":
      if (!rest[0]) fail("templates delete needs a template ID");
      await admin.templates.delete(rest[0]);
      process.stdout.write("deleted\n");
      return;
    case "templates build": {
      if (!values.name) fail("templates build needs --name");
      let image = values.image;
      if (values.dockerfile) {
        if (!values.repository) fail("--dockerfile needs --repository <the stack's EcrRepositoryUri output>");
        image = buildAndPush(values.dockerfile, values.context ?? dirname(resolve(values.dockerfile)), values.repository, values.name);
      }
      if (!image) fail("templates build needs --image or --dockerfile");
      const envVars = Object.fromEntries(
        (values.env ?? []).map((kv) => {
          const i = kv.indexOf("=");
          if (i <= 0) fail(`--env must be KEY=VALUE, got ${kv}`);
          return [kv.slice(0, i), kv.slice(i + 1)];
        }),
      );
      const num = (v: string | undefined, flag: string) => {
        if (v === undefined) return undefined;
        const n = Number(v);
        if (!Number.isInteger(n) || n <= 0) fail(`${flag} must be a positive integer`);
        return n;
      };
      const t = await admin.templates.build({
        name: values.name,
        image,
        cpuCount: num(values.cpu, "--cpu"),
        memoryMB: num(values.memory, "--memory"),
        diskSizeMB: num(values.disk, "--disk"),
        startCmd: values["start-cmd"],
        readyCmd: values["ready-cmd"],
        envVars,
        public: values.public,
        teamId: values.team,
      });
      process.stdout.write(`${templateLine(t)}\n`);
      if (values.wait) {
        const ready = await admin.templates.waitUntilReady(t.templateId, { onLog: (l) => process.stderr.write(`  ${l}\n`) });
        process.stdout.write(`ready: ${templateLine(ready)}\n`);
      }
      return;
    }
    case "hosts":
      return print(await admin.hosts.list());
    case "sandboxes":
      return print(await admin.sandboxes.list());
    default:
      fail(`unknown command "${positionals.join(" ")}"; run \`weft-sandbox help\``);
  }
}

main(process.argv.slice(2)).catch((e: unknown) => fail(e instanceof Error ? e.message : String(e)));
