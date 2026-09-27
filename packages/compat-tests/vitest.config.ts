import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["js/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Sandboxes are real; keep concurrency modest.
    maxWorkers: 4,
  },
});
