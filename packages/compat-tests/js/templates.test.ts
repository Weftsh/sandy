import { Sandbox, Template } from "e2b";
import { describe, expect, it } from "vitest";

import { RUN_ID } from "./helpers.js";

const IMAGE = process.env.WEFT_DEV_IMAGE ?? "python:3.12-slim";

async function deleteTemplate(templateId: string): Promise<void> {
  const res = await fetch(`${process.env.E2B_API_URL}/weft/v1/templates/${templateId}`, {
    method: "DELETE",
    headers: { "X-API-Key": process.env.WEFT_ADMIN_KEY ?? "" },
  });
  expect(res.ok).toBe(true);
}

describe("templates (JS SDK)", () => {
  it("builds a template from an image and starts sandboxes from it", async () => {
    const name = `compat-js-${RUN_ID}`;
    const template = Template().fromImage(IMAGE).setEnvs({ COMPAT_TEMPLATE: "yes" }).setWorkdir("/srv");
    const info = await Template.build(template, name, { cpuCount: 1, memoryMB: 512 });
    const sbx = await Sandbox.create(name, { timeoutMs: 60_000 });
    try {
      const out = await sbx.commands.run("echo $COMPAT_TEMPLATE; pwd");
      expect(out.stdout.split(/\s+/).filter(Boolean)).toEqual(["yes", "/srv"]);
    } finally {
      await sbx.kill();
      await deleteTemplate(info.templateId);
    }
  }, 300_000);
});
