import { CommandExitError } from "e2b";
import { describe, expect, it } from "vitest";

import { withSandbox } from "./helpers.js";

describe("commands (JS SDK)", () => {
  it("runs, streams and reports exit codes", async () => {
    await withSandbox("commands", async (sbx) => {
      const r = await sbx.commands.run("echo out; echo err 1>&2");
      expect([r.exitCode, r.stdout, r.stderr]).toEqual([0, "out\n", "err\n"]);
      const chunks: string[] = [];
      await sbx.commands.run("for i in 1 2 3; do echo $i; done", { onStdout: (d) => void chunks.push(d) });
      expect(chunks.join("")).toBe("1\n2\n3\n");
      await expect(sbx.commands.run("exit 5")).rejects.toBeInstanceOf(CommandExitError);
      expect((await sbx.commands.run("whoami", { user: "root" })).stdout.trim()).toBe("root");
    });
  });

  it("runs background processes with stdin", async () => {
    await withSandbox("background", async (sbx) => {
      const h = await sbx.commands.run("read x; echo got-$x", { background: true, stdin: true });
      await sbx.commands.sendStdin(h.pid, "value\n");
      const done = await h.wait();
      expect(done.stdout.trim()).toBe("got-value");
      const sleeper = await sbx.commands.run("sleep 300", { background: true });
      expect((await sbx.commands.list()).map((p) => p.pid)).toContain(sleeper.pid);
      expect(await sbx.commands.kill(sleeper.pid)).toBe(true);
    });
  });
});
