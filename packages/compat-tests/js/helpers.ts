import { Sandbox } from "e2b";

export const RUN_ID = Math.random().toString(36).slice(2, 10);

export function tag(name: string): Record<string, string> {
  return { suite: "compat-js", run: RUN_ID, test: name.slice(0, 60) };
}

export async function withSandbox<T>(name: string, fn: (sbx: Sandbox) => Promise<T>): Promise<T> {
  const sbx = await Sandbox.create({ metadata: tag(name), timeoutMs: 120_000 });
  try {
    return await fn(sbx);
  } finally {
    await Sandbox.kill(sbx.sandboxId).catch(() => {});
  }
}
