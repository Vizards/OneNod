import { readFile, readdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const options = parseOptions(process.argv.slice(2));
const releaseEnvironment = {
  ...process.env,
  ONENOD_RELEASE_TAG: `v${options.version}`,
  ONENOD_RELEASE_VERSION: options.version,
  ONENOD_SOURCE_COMMIT: options.commit,
  SOURCE_DATE_EPOCH: commitTimestamp(options.commit),
  VITE_ONENOD_RELEASE_TAG: `v${options.version}`,
  VITE_ONENOD_RELEASE_VERSION: options.version,
  VITE_ONENOD_SOURCE_COMMIT: options.commit,
  WRANGLER_LOG_SANITIZE: "true",
  WRANGLER_WRITE_LOGS: "false",
};

verifyCheckout(options.commit);
await rm(resolve(repositoryRoot, "apps/gateway/dist"), {
  force: true,
  recursive: true,
});
await rm(resolve(repositoryRoot, "apps/executor/dist"), {
  force: true,
  recursive: true,
});

run("pnpm", ["--filter", "@onenod/protocol", "build"], releaseEnvironment);
run("pnpm", ["--filter", "@onenod/gateway", "build:web"], releaseEnvironment);
runWrangler("gateway", releaseEnvironment);
run("pnpm", ["--filter", "@onenod/executor", "build:core"], releaseEnvironment);
runWrangler("executor", releaseEnvironment);
run(
  "node",
  ["apps/executor/scripts/audit-artifact.mjs"],
  releaseEnvironment,
);

await assertBuildMetadata(
  resolve(repositoryRoot, "apps/gateway/dist/worker/index.js"),
  options,
  "Gateway Worker",
);
await assertBuildMetadata(
  resolve(repositoryRoot, "apps/executor/dist/worker/index.js"),
  options,
  "Executor Worker",
);
const webAssets = await findJavaScriptAssets(
  resolve(repositoryRoot, "apps/gateway/dist/web/assets"),
);
if (webAssets.length === 0) fail("PWA build did not produce a JavaScript asset");
if (
  !(await Promise.all(
    webAssets.map(async (path) => {
      const content = await readFile(path, "utf8");
      return content.includes(options.version) && content.includes(options.commit);
    }),
  )).some(Boolean)
) {
  fail("PWA assets do not contain the release version and source commit");
}

run(
  "node",
  [
    "scripts/release/package-artifact.mjs",
    "deployment",
    "--components",
    options.components,
    "--notices",
    options.notices,
    "--version",
    options.version,
    "--commit",
    options.commit,
    "--output",
    options.output,
  ],
  releaseEnvironment,
);

function runWrangler(component, environment) {
  const packageRoot = resolve(repositoryRoot, `apps/${component}`);
  const executable = resolve(packageRoot, "node_modules/.bin/wrangler");
  run(
    executable,
    [
      "deploy",
      "--dry-run",
      "--cwd",
      packageRoot,
      "--config",
      resolve(packageRoot, "wrangler.jsonc"),
      "--outdir",
      resolve(packageRoot, "dist/worker"),
      "--define",
      `ONENOD_RELEASE_VERSION:${JSON.stringify(options.version)}`,
      "--define",
      `ONENOD_SOURCE_COMMIT:${JSON.stringify(options.commit)}`,
      "--define",
      `ONENOD_RELEASE_TAG:${JSON.stringify(`v${options.version}`)}`,
    ],
    environment,
  );
}

function run(command, args, environment) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: environment,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    fail(`${command} failed with status ${result.status ?? "signal"}`);
  }
}

function verifyCheckout(commit) {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.status !== 0 || result.stdout.trim() !== commit) {
    fail("release build checkout does not match the tagged source commit");
  }
}

function commitTimestamp(commit) {
  const result = spawnSync("git", ["show", "-s", "--format=%ct", commit], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  const value = result.stdout.trim();
  if (result.status !== 0 || !/^[1-9]\d*$/u.test(value)) {
    fail("could not resolve the release commit timestamp");
  }
  return value;
}

async function assertBuildMetadata(path, values, label) {
  const content = await readFile(path, "utf8").catch(() => "");
  if (!content.includes(values.version) || !content.includes(values.commit)) {
    fail(`${label} does not contain the release version and source commit`);
  }
}

async function findJavaScriptAssets(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".js"))
    .map((entry) => resolve(directory, entry.name));
}

function parseOptions(args) {
  const values = { commit: "", components: "", notices: "", output: "", version: "" };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--commit":
        values.commit = value;
        break;
      case "--components":
        values.components = resolve(value);
        break;
      case "--notices":
        values.notices = resolve(value);
        break;
      case "--output":
        values.output = resolve(value);
        break;
      case "--version":
        values.version = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  if (!/^[0-9a-f]{40}$/u.test(values.commit)) {
    fail("source commit must be a full lowercase Git SHA");
  }
  if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(values.version)) {
    fail("release version must be a stable semantic version");
  }
  if (values.output === "" || values.notices === "" || values.components === "") {
    fail("release output, notices, and component inventory are required");
  }
  return values;
}

function fail(message) {
  throw new Error(`release_deployment_build_failed:${message}`);
}
