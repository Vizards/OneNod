import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";

import {
  compareProductVersions,
  parseStableVersion,
  releaseTrainTarget,
  validateReleaseChannelContract,
} from "./release-version.mjs";
import { validateReleaseWorkflow } from "./release-workflow-contract.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const sourceCommit = parseOptions(process.argv.slice(2));
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
const releaseWorkflowText = await readSourceText(contract.workflow);
try {
  validateReleaseWorkflow(releaseWorkflowText);
} catch (error) {
  fail(error instanceof Error ? error.message : "release workflow is invalid");
}
const helperSourceDigest = await digestHelperSources();
if (contract.components?.keychain_helper?.source_digest !== helperSourceDigest) {
  fail(
    `Keychain helper source changed without updating its independent release contract (${helperSourceDigest})`,
  );
}
const coreEvidence = await readJSON("apps/executor/evidence/expected-core.json");
const coreLicense = await readSourceBytes(
  "apps/executor/third_party/licenses/onepassword-sdk-go-0.4.1.txt",
);
const ssh2License = await readSourceBytes(
  "apps/executor/third_party/licenses/ssh2-1.17.0.txt",
);
const saferBufferLicense = await readSourceBytes(
  "apps/executor/third_party/licenses/safer-buffer-2.1.2.txt",
);
const ssh2Patch = await readSourceText("patches/ssh2@1.17.0.patch");
const saferBufferAdapter = await readSourceText(
  "apps/executor/src/safer-buffer-worker.cjs",
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

const goModule = await readSourceText("cmd/may/go.mod");
if (!goModule.startsWith("module github.com/Vizards/OneNod/cmd/may\n")) {
  fail("may Go module does not use the canonical repository identity");
}
const helperMain = await readSourceBytes("cmd/may/keychainhelper/main.go").catch(
  () => null,
);
if (helperMain === null || helperMain.byteLength === 0) {
  fail("the independently versioned Keychain helper source is missing");
}

process.stdout.write(
  `${JSON.stringify({
    event: "release_source_contract_verified",
    packages: versionedPackages.length,
    release_train_target: releaseTrainTargetVersion,
    source_commit: sourceCommit ?? "working_tree",
    version: expectedVersion,
  })}\n`,
);

async function readJSON(path) {
  try {
    const parsed = JSON.parse(await readSourceText(path));
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
  const directory = "cmd/may/keychainhelper";
  const names = (await listSourceNames(directory))
    .filter((name) => name.endsWith(".go") && !name.endsWith("_test.go"))
    .sort((left, right) => left.localeCompare(right, "en"));
  if (names.length === 0) fail("Keychain helper has no production Go sources");
  const hash = createHash("sha256");
  for (const name of names) {
    const content = await readSourceBytes(`${directory}/${name}`);
    hash.update(name);
    hash.update("\0");
    hash.update(String(content.byteLength));
    hash.update("\0");
    hash.update(content);
  }
  return `sha256:${hash.digest("hex")}`;
}

async function readSourceText(path) {
  return (await readSourceBytes(path)).toString("utf8");
}

async function readSourceBytes(path) {
  if (sourceCommit === null) {
    return readFile(resolve(repositoryRoot, path));
  }
  return gitBytes(["show", `${sourceCommit}:${path}`], `read ${path}`);
}

async function listSourceNames(path) {
  if (sourceCommit === null) {
    return readdir(resolve(repositoryRoot, path));
  }
  const output = gitBytes(
    ["ls-tree", "-z", "--name-only", `${sourceCommit}:${path}`],
    `list ${path}`,
  );
  return output
    .toString("utf8")
    .split("\0")
    .filter((name) => name !== "");
}

function gitBytes(arguments_, label) {
  const result = spawnSync("git", arguments_, {
    cwd: repositoryRoot,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error !== undefined || result.status !== 0) {
    fail(`cannot ${label} from selected source commit`);
  }
  return result.stdout;
}

function parseOptions(arguments_) {
  if (arguments_.length === 0) return null;
  if (
    arguments_.length !== 2 ||
    arguments_[0] !== "--source-sha" ||
    !/^[0-9a-f]{40}$/u.test(arguments_[1])
  ) {
    fail("usage: verify-source-contract.mjs [--source-sha <40-lowercase-hex>]");
  }
  return arguments_[1];
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
