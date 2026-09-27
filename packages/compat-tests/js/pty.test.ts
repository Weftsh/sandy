import { describe, expect, it } from "vitest";

import { withSandbox } from "./helpers.js";

describe("pty (JS SDK)", () => {
  it("runs an interactive terminal", async () => {
    await withSandbox("pty", async (sbx) => {
      let out = "";
      const dec = new TextDecoder();
      const pty = await sbx.pty.create({ cols: 100, rows: 30, onData: (d) => void (out += dec.decode(d)) });
      await sbx.pty.resize(pty.pid, { cols: 120, rows: 40 });
      await sbx.pty.sendInput(pty.pid, new TextEncoder().encode("stty size; echo js-$((6*7)); exit\n"));
      await pty.wait();
      expect(out).toContain("js-42");
      expect(out).toContain("40 120");
    });
  });
});
