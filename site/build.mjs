// Builds the static site into dist/: copies the pages and public files, then
// compiles and minifies the Tailwind stylesheet. `--watch` rebuilds the CSS
// on change for local editing.
import { spawnSync, spawn } from "node:child_process";
import { cpSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

const here = import.meta.dirname;
const dist = join(here, "dist");
const watch = process.argv.includes("--watch");

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, "assets"), { recursive: true });
cpSync(join(here, "public"), dist, { recursive: true });
for (const f of readdirSync(join(here, "src")).filter((f) => f.endsWith(".html"))) {
  cpSync(join(here, "src", f), join(dist, f));
}

const args = ["-i", join(here, "src", "site.css"), "-o", join(dist, "assets", "site.css"), "--minify"];
const bin = join(here, "node_modules", ".bin", "tailwindcss");
if (watch) {
  spawn(bin, [...args, "--watch"], { stdio: "inherit" });
} else {
  const r = spawnSync(bin, args, { stdio: "inherit" });
  process.exit(r.status ?? 1);
}
