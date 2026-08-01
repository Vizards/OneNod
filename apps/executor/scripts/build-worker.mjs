import { spawnSync } from "node:child_process";
import { rm } from "node:fs/promises";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const outputDirectory = resolve(packageRoot, "dist/worker");
const wrangler = resolve(packageRoot, "node_modules/.bin/wrangler");
const configPath = resolve(packageRoot, "wrangler.jsonc");

await rm(outputDirectory, { force: true, recursive: true });

const build = spawnSync(
  wrangler,
  [
    "deploy",
    "--dry-run",
    "--cwd",
    packageRoot,
    "--config",
    configPath,
    "--outdir",
    outputDirectory,
  ],
  {
    cwd: packageRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      WRANGLER_LOG_SANITIZE: "true",
      WRANGLER_WRITE_LOGS: "false",
    },
  },
);

process.stdout.write(build.stdout);
process.stderr.write(build.stderr);
if (build.status !== 0) {
  throw new Error(`Wrangler dry-run failed (${build.status ?? "signal"})`);
}
