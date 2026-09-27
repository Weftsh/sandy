import { Sandbox } from "e2b";
import { describe, expect, it } from "vitest";

import { tag, withSandbox } from "./helpers.js";

describe("lifecycle (JS SDK)", () => {
  it("creates, lists by metadata and kills", async () => {
    const meta = tag("create-list-kill");
    const sbx = await Sandbox.create({ metadata: meta, timeoutMs: 60_000 });
    const listed = await Sandbox.list({ query: { metadata: meta } }).nextItems();
    expect(listed.map((s) => s.sandboxId)).toEqual([sbx.sandboxId]);
    expect(await sbx.isRunning()).toBe(true);
    expect(await sbx.kill()).toBe(true);
    // The JS SDK reads `code` from the error body to return false.
    expect(await Sandbox.kill(sbx.sandboxId)).toBe(false);
  });

  it("reports sandbox info", async () => {
    await withSandbox("info", async (sbx) => {
      const info = await sbx.getInfo();
      expect(info.sandboxId).toBe(sbx.sandboxId);
      expect(info.state).toBe("running");
      expect(info.metadata.suite).toBe("compat-js");
    });
  });

  it("pauses and resumes through connect", async () => {
    await withSandbox("pause-resume", async (sbx) => {
      await sbx.files.write("/home/user/p.txt", "kept");
      expect(await sbx.pause()).toBe(true);
      expect((await Sandbox.getInfo(sbx.sandboxId)).state).toBe("paused");
      const resumed = await Sandbox.connect(sbx.sandboxId);
      expect(await resumed.files.read("/home/user/p.txt")).toBe("kept");
    });
  });

  it("extends the timeout", async () => {
    await withSandbox("timeout", async (sbx) => {
      const before = (await sbx.getInfo()).endAt;
      await sbx.setTimeout(600_000);
      expect((await sbx.getInfo()).endAt.getTime()).toBeGreaterThan(before.getTime());
    });
  });
});
