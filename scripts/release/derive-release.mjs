import { appendFile, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const options = parseOptions(process.argv.slice(2));
const manifestPath = resolve(repositoryRoot, ".release-please-manifest.json");
const contractPath = resolve(import.meta.dirname, "release-contract.json");

const manifest = parseRecord(await readFile(manifestPath, "utf8"), "release manifest");
const contract = parseRecord(await readFile(contractPath, "utf8"), "release contract");
const version = strictVersion(manifest["."], "release manifest version");
const sourceSha = strictCommit(options.sha);
const helperVersion = strictVersion(
  contract.components?.keychain_helper?.version,
  "Keychain helper version",
);
const helperSourceDigest = strictDigest(
  contract.components?.keychain_helper?.source_digest,
  "Keychain helper source digest",
);

let shouldRelease = false;
let reason;
let previousVersion = "";
if (options.event === "workflow_dispatch") {
  const requested = strictVersion(options.versionInput, "requested release version");
  if (requested !== version) {
    fail(`requested version ${requested} does not match manifest version ${version}`);
  }
  ensurePublicVersion(version);
  if (options.ref !== `refs/tags/v${version}`) {
    fail("manual release retries must run from the exact immutable release tag");
  }
  previousVersion = previousReleaseVersion(sourceSha, version);
  shouldRelease = true;
  reason = "manual_retry";
} else if (options.event === "push") {
  if (options.ref !== "refs/heads/main") {
    fail("automatic releases must run from refs/heads/main");
  }
  const previousManifest = readPreviousManifest(sourceSha);
  if (previousManifest === null) {
    reason = "initial_manifest_baseline";
  } else {
    const candidatePreviousVersion = strictVersion(
      previousManifest["."],
      "previous release manifest version",
    );
    requireExactFirstPublicVersion(candidatePreviousVersion, version);
    if (compareVersions(version, candidatePreviousVersion) <= 0) {
      fail(
        `release manifest must increase monotonically (${candidatePreviousVersion} -> ${version})`,
      );
    }
    ensurePublicVersion(version);
    previousVersion = version === "0.0.1" ? "" : candidatePreviousVersion;
    shouldRelease = true;
    reason = "manifest_version_advanced";
  }
} else {
  fail(`unsupported workflow event ${JSON.stringify(options.event)}`);
}

const result = {
  helper_changed: shouldRelease
    ? helperChanged(previousVersion, helperVersion, helperSourceDigest)
    : false,
  helper_source_digest: helperSourceDigest,
  helper_version: helperVersion,
  previous_version: previousVersion,
  reason,
  should_release: shouldRelease,
  source_sha: sourceSha,
  tag: shouldRelease ? `v${version}` : "",
  version,
};

if (options.output !== "") {
  await appendFile(
    options.output,
    Object.entries(result)
      .map(([key, value]) => `${key}=${String(value)}`)
      .join("\n") + "\n",
    "utf8",
  );
}
process.stdout.write(`${JSON.stringify(result)}\n`);

function parseOptions(args) {
  const parsed = {
    event: "",
    output: "",
    ref: "",
    sha: "",
    versionInput: "",
  };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--event":
        parsed.event = value;
        break;
      case "--output":
        parsed.output = value;
        break;
      case "--ref":
        parsed.ref = value;
        break;
      case "--sha":
        parsed.sha = value;
        break;
      case "--version-input":
        parsed.versionInput = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  if (parsed.event === "" || parsed.ref === "" || parsed.sha === "") {
    fail(
      "usage: derive-release.mjs --event <push|workflow_dispatch> --ref <git-ref> --sha <commit> [--version-input <version>] [--output <path>]",
    );
  }
  return parsed;
}

function readPreviousManifest(sourceShaValue) {
  const result = spawnSync(
    "git",
    ["show", `${sourceShaValue}^1:.release-please-manifest.json`],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status !== 0) {
    return null;
  }
  return parseRecord(result.stdout, "previous release manifest");
}

function previousReleaseVersion(sourceShaValue, currentVersion) {
  const previousManifest = readPreviousManifest(sourceShaValue);
  if (previousManifest === null) {
    fail("manual release retries must run against the release commit");
  }
  const previous = strictVersion(
    previousManifest["."],
    "previous release manifest version",
  );
  requireExactFirstPublicVersion(previous, currentVersion);
  if (compareVersions(currentVersion, previous) <= 0) {
    fail("manual release retries must select a commit that advances the manifest");
  }
  return currentVersion === "0.0.1" ? "" : previous;
}

function requireExactFirstPublicVersion(previousVersion, currentVersion) {
  if (previousVersion === "0.0.0" && currentVersion !== "0.0.1") {
    fail("the first public release after the 0.0.0 baseline must be exactly 0.0.1");
  }
}

function helperChanged(
  previousVersionValue,
  currentHelperVersion,
  currentSourceDigest,
) {
  if (previousVersionValue === "") return true;
  const result = spawnSync(
    "git",
    [
      "show",
      `refs/tags/v${previousVersionValue}:scripts/release/release-contract.json`,
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status !== 0) {
    fail("cannot inspect the previous Keychain helper release contract");
  }
  const previous = parseRecord(result.stdout, "previous release contract");
  const previousHelperVersion = strictVersion(
    previous.components?.keychain_helper?.version,
    "previous Keychain helper version",
  );
  const previousSourceDigest = strictDigest(
    previous.components?.keychain_helper?.source_digest,
    "previous Keychain helper source digest",
  );
  const versionChanged = previousHelperVersion !== currentHelperVersion;
  const sourceChanged = previousSourceDigest !== currentSourceDigest;
  if (versionChanged !== sourceChanged) {
    fail(
      "Keychain helper version and production source digest must change together",
    );
  }
  return versionChanged;
}

function parseRecord(value, label) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(`${label} is not valid JSON`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail(`${label} must be a JSON object`);
  }
  return parsed;
}

function strictVersion(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(value)) {
    fail(`${label} must be a stable semantic version`);
  }
  return value;
}

function strictCommit(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
    fail("source commit must be a full lowercase Git SHA");
  }
  return value;
}

function strictDigest(value, label) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail(`${label} must be a SHA-256 digest`);
  }
  return value;
}

function ensurePublicVersion(value) {
  if (compareVersions(value, "0.0.1") < 0) {
    fail("the first public release is v0.0.1");
  }
}

function compareVersions(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] - rightParts[index];
    }
  }
  return 0;
}

function fail(message) {
  throw new Error(`release_derivation_failed:${message}`);
}
