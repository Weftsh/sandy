import { FileType, FilesystemEventType } from "e2b";
import { describe, expect, it } from "vitest";

import { withSandbox } from "./helpers.js";

describe("files (JS SDK)", () => {
  it("writes, reads and manages files", async () => {
    await withSandbox("files", async (sbx) => {
      await sbx.files.write("/home/user/a.txt", "alpha");
      expect(await sbx.files.read("/home/user/a.txt")).toBe("alpha");
      const bytes = new Uint8Array(1024 * 1024).map((_, i) => i % 251);
      await sbx.files.write("/home/user/b.bin", bytes.buffer);
      expect(new Uint8Array(await sbx.files.read("/home/user/b.bin", { format: "bytes" }))).toEqual(bytes);
      await sbx.files.write([
        { path: "/home/user/m/1.txt", data: "1" },
        { path: "/home/user/m/2.txt", data: "2" },
      ]);
      const entries = await sbx.files.list("/home/user/m");
      expect(entries.map((e) => [e.name, e.type]).sort()).toEqual([
        ["1.txt", FileType.FILE],
        ["2.txt", FileType.FILE],
      ]);
      expect(await sbx.files.makeDir("/home/user/m")).toBe(false);
      await sbx.files.rename("/home/user/m/1.txt", "/home/user/m/3.txt");
      expect(await sbx.files.exists("/home/user/m/3.txt")).toBe(true);
      await sbx.files.remove("/home/user/m");
      expect(await sbx.files.exists("/home/user/m")).toBe(false);
    });
  });

  it("streams directory watch events", async () => {
    await withSandbox("watch", async (sbx) => {
      const events: FilesystemEventType[] = [];
      const handle = await sbx.files.watchDir("/home/user", (e) => void events.push(e.type));
      await sbx.files.write("/home/user/watched.txt", "x");
      await new Promise((r) => setTimeout(r, 1000));
      await handle.stop();
      expect(events).toContain(FilesystemEventType.CREATE);
    });
  });
});
