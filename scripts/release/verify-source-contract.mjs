import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { resolve } from "node:path";

import {
  compareProductVersions,
  parseStableVersion,
  releaseTrainTarget,
  validateReleaseChannelContract,
} from "./release-version.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const manifest = await readJSON(".release-please-manifest.json");
const config = await readJSON("release-please-config.json");
const contract = await readJSON("scripts/release/release-contract.json");
const expectedVersion = strictVersion(manifest["."], "release-please manifest");
const releaseTrainTargetVersion = releaseTrainTarget(contract);
const versionedPackages = [
  "package.json",
  "apps/gateway/package.json",
  "apps/executor/package.json",
  "packages/protocol/package.json",
];
const extraVersionedPackages = versionedPackages.filter(
  (path) => path !== "package.json",
);

for (const path of versionedPackages) {
  const packageManifest = await readJSON(path);
  const actual = strictVersion(packageManifest.version, `${path} version`);
  if (actual !== expectedVersion) {
    fail(`${path} version ${actual} differs from release version ${expectedVersion}`);
  }
}

const configuredExtraFiles = config.packages?.["."]?.["extra-files"];
if (!Array.isArray(configuredExtraFiles)) {
  fail("release-please extra-files are missing");
}
const configuredPaths = configuredExtraFiles
  .map((entry) => entry?.path)
  .filter((path) => typeof path === "string")
  .sort();
if (
  JSON.stringify(configuredPaths) !==
  JSON.stringify([...extraVersionedPackages].sort())
) {
  fail("release-please does not update the complete unified package-version set");
}
if (
  config.packages?.["."]?.["release-type"] !== "node" ||
  config.packages?.["."]?.["initial-version"] !== "0.0.1" ||
  contract.repository !== "Vizards/OneNod" ||
  contract.workflow !== ".github/workflows/release.yml" ||
  releaseTrainTargetVersion === null ||
  compareProductVersions(releaseTrainTargetVersion, expectedVersion) < 0 ||
  !validateReleaseChannelContract(contract)
) {
  fail("canonical release identity is inconsistent");
}
const releaseWorkflow = await readFile(
  resolve(repositoryRoot, contract.workflow),
  "utf8",
);
for (const jobName of [
  "local-artifacts",
  "deployment-artifacts",
  "sbom",
  "publish",
]) {
  const job = workflowJob(releaseWorkflow, jobName);
  if (
    !job.includes("uses: pnpm/action-setup@") ||
    !job.includes("cache: pnpm") ||
    !job.includes("run: pnpm install --frozen-lockfile")
  ) {
    fail(`release job ${jobName} does not install the frozen Node dependency set`);
  }
}
const prepareJob = workflowJob(releaseWorkflow, "prepare");
if (
  !prepareJob.includes("name: Check out the reviewed release controller") ||
  !prepareJob.includes("branches-where-head") ||
  !prepareJob.includes("--source-sha \"$SOURCE_SHA_INPUT\"") ||
  !prepareJob.includes("github.ref == 'refs/heads/main'") ||
  !prepareJob.includes("Require a GitHub-verified source commit signature") ||
  !prepareJob.includes("GITHUB_STEP_SUMMARY") ||
  prepareJob.includes("contents: write") ||
  prepareJob.includes("Create or verify the exact lightweight tag")
) {
  fail(
    "prepare job must produce a read-only, signed-source plan through the reviewed main controller",
  );
}
const authorizeJob = workflowJob(releaseWorkflow, "authorize");
if (
  !authorizeJob.includes("needs: prepare") ||
  !authorizeJob.includes("github.ref == 'refs/heads/main'") ||
  !authorizeJob.includes("name: ${{ github.event_name == 'workflow_dispatch'") ||
  !authorizeJob.includes("contents: write") ||
  !authorizeJob.includes("Create or verify the exact lightweight tag")
) {
  fail("authorize job must gate and bind the exact reviewed release plan");
}
for (const jobName of ["local-artifacts", "deployment-artifacts"]) {
  if (!workflowJob(releaseWorkflow, jobName).includes("- authorize")) {
    fail(`release build job ${jobName} must wait for release authorization`);
  }
}
const publishJob = workflowJob(releaseWorkflow, "publish");
if (
  !publishJob.includes("name: Check out the reviewed release controller") ||
  !publishJob.includes("ref: ${{ github.sha }}") ||
  !publishJob.includes("- authorize") ||
  !publishJob.includes("needs.authorize.result == 'success'") ||
  !publishJob.includes("github.ref == 'refs/heads/main'") ||
  !publishJob.includes('run: test "$(git rev-parse HEAD)" = "$WORKFLOW_SHA"') ||
  publishJob.includes("refs/tags/${{ needs.prepare.outputs.tag }}") ||
  publishJob.includes(".release-controller") ||
  (publishJob.match(
    /node scripts\/release\/verify-github-release\.mjs/gu,
  )?.length ?? 0) !== 2
) {
  fail(
    "publish job must execute only the reviewed main controller while handling candidate artifacts",
  );
}
const helperSourceDigest = await digestHelperSources();
if (contract.components?.keychain_helper?.source_digest !== helperSourceDigest) {
  fail(
    `Keychain helper source changed without updating its independent release contract (${helperSourceDigest})`,
  );
}
const coreEvidence = await readJSON("apps/executor/evidence/expected-core.json");
const coreLicense = await readFile(
  resolve(
    repositoryRoot,
    "apps/executor/third_party/licenses/onepassword-sdk-go-0.4.1.txt",
  ),
);
const ssh2License = await readFile(
  resolve(repositoryRoot, "apps/executor/third_party/licenses/ssh2-1.17.0.txt"),
);
const saferBufferLicense = await readFile(
  resolve(
    repositoryRoot,
    "apps/executor/third_party/licenses/safer-buffer-2.1.2.txt",
  ),
);
const ssh2Patch = await readFile(
  resolve(repositoryRoot, "patches/ssh2@1.17.0.patch"),
  "utf8",
);
const saferBufferAdapter = await readFile(
  resolve(repositoryRoot, "apps/executor/src/safer-buffer-worker.cjs"),
  "utf8",
);
if (
  coreEvidence.repository !== "https://github.com/1Password/onepassword-sdk-go" ||
  coreEvidence.sourceTag !== "v0.4.1" ||
  coreEvidence.license !== "MIT" ||
  coreEvidence.copyright !== "Copyright (c) 2024 1Password" ||
  coreEvidence.licenseSha256 !==
    createHash("sha256").update(coreLicense).digest("hex") ||
  createHash("sha256").update(ssh2License).digest("hex") !==
    "9f75981e6039d13bf2e591c59e9c89a2641ca605fde59ba78974b11553f6c148" ||
  createHash("sha256").update(saferBufferLicense).digest("hex") !==
    "4bc935e71be198c67ddf3c2b5fddb195f6edc182bfc155a96a6db61b44b494b9" ||
  !coreLicense.toString("utf8").includes(coreEvidence.copyright) ||
  !ssh2License.toString("utf8").includes("Copyright Brian White") ||
  !ssh2Patch.includes("diff --git a/lib/protocol/keyParser.js") ||
  !saferBufferAdapter.includes("Adapted from safer-buffer 2.1.2") ||
  !saferBufferAdapter.includes("third_party/licenses/safer-buffer-2.1.2.txt")
) {
  fail("vendored Worker source attribution or license material is inconsistent");
}

const goModule = await readFile(resolve(repositoryRoot, "cmd/may/go.mod"), "utf8");
if (!goModule.startsWith("module github.com/Vizards/OneNod/cmd/may\n")) {
  fail("may Go module does not use the canonical repository identity");
}
const helperMain = resolve(repositoryRoot, "cmd/may/keychainhelper/main.go");
const helperInfo = await stat(helperMain).catch(() => null);
if (helperInfo === null || !helperInfo.isFile() || helperInfo.size <= 0) {
  fail("the independently versioned Keychain helper source is missing");
}

process.stdout.write(
  `${JSON.stringify({
    event: "release_source_contract_verified",
    packages: versionedPackages.length,
    release_train_target: releaseTrainTargetVersion,
    version: expectedVersion,
  })}\n`,
);

async function readJSON(path) {
  try {
    const parsed = JSON.parse(await readFile(resolve(repositoryRoot, path), "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      fail(`${path} must contain a JSON object`);
    }
    return parsed;
  } catch (error) {
    if (error instanceof SyntaxError) fail(`${path} is not valid JSON`);
    throw error;
  }
}

async function digestHelperSources() {
  const directory = resolve(repositoryRoot, "cmd/may/keychainhelper");
  const names = (await readdir(directory))
    .filter((name) => name.endsWith(".go") && !name.endsWith("_test.go"))
    .sort((left, right) => left.localeCompare(right, "en"));
  if (names.length === 0) fail("Keychain helper has no production Go sources");
  const hash = createHash("sha256");
  for (const name of names) {
    const content = await readFile(resolve(directory, name));
    hash.update(name);
    hash.update("\0");
    hash.update(String(content.byteLength));
    hash.update("\0");
    hash.update(content);
  }
  return `sha256:${hash.digest("hex")}`;
}

function workflowJob(workflow, name) {
  const marker = `  ${name}:\n`;
  const start = workflow.indexOf(marker);
  if (start === -1) fail(`release workflow job ${name} is missing`);
  const remainder = workflow.slice(start + marker.length);
  const nextJob = remainder.search(/^  [a-z][a-z0-9-]*:\n/mu);
  return nextJob === -1 ? remainder : remainder.slice(0, nextJob);
}

function strictVersion(value, label) {
  if (parseStableVersion(value) === null) {
    fail(`${label} must be a stable semantic version`);
  }
  return value;
}

function fail(message) {
  throw new Error(`release_source_contract_failed:${message}`);
}
