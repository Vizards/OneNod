import { spawnSync } from "node:child_process";
import { appendFile, readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  compareProductVersions,
  parseProductVersion,
  parseStableVersion,
  productVersionCore,
  releaseChannelPolicy,
  releaseMatchesTrain,
  releaseTrainTarget,
  validateReleaseChannelContract,
} from "./release-version.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const options = parseOptions(process.argv.slice(2));
const manifestPath = resolve(repositoryRoot, ".release-please-manifest.json");
const contractPath = resolve(import.meta.dirname, "release-contract.json");

const workflowSha = strictCommit(options.sha);
const publishedReleaseTags = await readPublishedReleaseTags(
  options.publishedReleaseTagsPath,
);
let sourceSha = workflowSha;
let manifest;
let contract;
let version;
let reason;
let shouldRelease = false;
let previousVersion = "";

if (options.event === "push") {
  requireMainRef("automatic releases");
  if (options.intent !== "") fail("automatic releases cannot declare a manual intent");
  manifest = parseRecord(await readFile(manifestPath, "utf8"), "release manifest");
  contract = parseRecord(await readFile(contractPath, "utf8"), "release contract");
  version = strictStableVersion(manifest["."], "release manifest version");

  const previousManifest = readPreviousManifest(sourceSha);
  if (previousManifest === null) {
    reason = "initial_manifest_baseline";
  } else {
    const candidatePreviousVersion = strictStableVersion(
      previousManifest["."],
      "previous release manifest version",
    );
    requireExactFirstPublicVersion(candidatePreviousVersion, version);
    if (compareProductVersions(version, candidatePreviousVersion) <= 0) {
      fail(
        `release manifest must increase monotonically (${candidatePreviousVersion} -> ${version})`,
      );
    }
    ensurePublicVersion(version);
    requireNewVersionAfterAllTags(version, sourceSha, publishedReleaseTags);
    previousVersion = version === "0.0.1" ? "" : candidatePreviousVersion;
    shouldRelease = true;
    reason = "manifest_version_advanced";
  }
} else if (options.event === "workflow_dispatch") {
  requireMainRef("manual releases");
  if (options.intent === "retry") {
    if (options.sourceSha !== "") {
      fail("manual release retries derive their source from the exact tag");
    }
    version = strictProductVersion(options.versionInput, "requested release version");
    ensurePublicVersion(version);
    const parsed = parseProductVersion(version);
    sourceSha = exactLightweightTagCommit(`v${version}`);
    requireRetryableUnpublishedTag(version, publishedReleaseTags);
    if (parsed.channel !== "alpha") requireAncestor(sourceSha, workflowSha);
    manifest = readRecordAt(
      sourceSha,
      ".release-please-manifest.json",
      "tagged release manifest",
    );
    contract = readRecordAt(
      sourceSha,
      "scripts/release/release-contract.json",
      "tagged release contract",
    );
    if (parsed.channel === "stable") {
      const taggedStableVersion = strictStableVersion(
        manifest["."],
        "tagged release manifest version",
      );
      if (taggedStableVersion !== version) {
        fail(
          `requested version ${version} does not match tagged manifest version ${taggedStableVersion}`,
        );
      }
      previousVersion = previousStableReleaseVersion(sourceSha, version);
    } else {
      strictStableVersion(manifest["."], "tagged stable baseline version");
      previousVersion = artifactPredecessorVersion(
        sourceSha,
        version,
        publishedReleaseTags,
      );
    }
    shouldRelease = true;
    reason = "manual_retry";
  } else if (options.intent === "alpha" || options.intent === "beta") {
    if (options.versionInput !== "") {
      fail(`new ${options.intent} releases derive their version automatically`);
    }
    if (options.intent === "alpha") {
      sourceSha = strictCommit(options.sourceSha);
      requireCommit(sourceSha, "candidate source");
      requireAncestor(
        workflowSha,
        sourceSha,
        "alpha source must contain the trusted main workflow commit",
      );
      requireSameRepositoryBranch(sourceSha);
    } else {
      if (options.sourceSha !== "") {
        fail("new beta releases derive their source from the trusted main workflow commit");
      }
      sourceSha = workflowSha;
    }

    const reviewedManifest = readRecordAt(
      workflowSha,
      ".release-please-manifest.json",
      "reviewed release manifest",
    );
    const reviewedContract = readRecordAt(
      workflowSha,
      "scripts/release/release-contract.json",
      "reviewed release contract",
    );
    manifest = readRecordAt(
      sourceSha,
      ".release-please-manifest.json",
      "candidate release manifest",
    );
    contract = readRecordAt(
      sourceSha,
      "scripts/release/release-contract.json",
      "candidate release contract",
    );
    requireReviewedReleasePolicy(reviewedContract, contract);
    const stableBaseline = strictStableVersion(
      reviewedManifest["."],
      "release-please stable baseline",
    );
    const candidateBaseline = strictStableVersion(
      manifest["."],
      "candidate release-please stable baseline",
    );
    if (candidateBaseline !== stableBaseline) {
      fail("candidate branch must preserve the reviewed stable release baseline");
    }
    const reviewedTrain = releaseTrainTarget(reviewedContract);
    if (reviewedTrain === null) {
      fail("reviewed release train target must be a stable semantic version");
    }
    version = nextPrereleaseVersion(reviewedTrain, options.intent);
    requireMissingTag(`v${version}`);
    if (compareProductVersions(version, stableBaseline) <= 0) {
      fail(`prerelease ${version} must be newer than stable baseline ${stableBaseline}`);
    }
    requireNewVersionAfterAllTags(version, sourceSha, publishedReleaseTags);
    previousVersion = artifactPredecessorVersion(
      sourceSha,
      version,
      publishedReleaseTags,
    );
    shouldRelease = true;
    reason = `derived_${options.intent}`;
  } else {
    fail("workflow_dispatch intent must be retry, alpha, or beta");
  }
} else {
  fail(`unsupported workflow event ${JSON.stringify(options.event)}`);
}

const stableBaselineVersion = strictStableVersion(
  manifest["."],
  "release-please stable baseline",
);
if (!validateReleaseChannelContract(contract)) {
  fail("release channel contract is invalid");
}
const releaseTrainTargetVersion = releaseTrainTarget(contract);
if (releaseTrainTargetVersion === null) {
  fail("release train target must be a stable semantic version");
}
if (
  shouldRelease &&
  options.intent !== "retry" &&
  !releaseMatchesTrain(contract, version)
) {
  fail(
    `new release ${version} must use reviewed release train ${releaseTrainTargetVersion}`,
  );
}
const policy = releaseChannelPolicy(contract, version);
if (policy === null) fail("release channel policy does not match the release version");
const helperVersion = strictStableVersion(
  contract.components?.keychain_helper?.version,
  "Keychain helper version",
);
const helperSourceDigest = strictDigest(
  contract.components?.keychain_helper?.source_digest,
  "Keychain helper source digest",
);
const artifactPredecessor = shouldRelease
  ? artifactPredecessorVersion(sourceSha, version, publishedReleaseTags)
  : "";

const result = {
  artifact_predecessor_version: artifactPredecessor,
  channel: policy.channel,
  github_latest: policy.github_latest,
  github_prerelease: policy.github_prerelease,
  helper_changed: shouldRelease
    ? helperChanged(
        artifactPredecessor,
        version,
        helperVersion,
        helperSourceDigest,
        publishedReleaseTags,
      )
    : false,
  helper_source_digest: helperSourceDigest,
  helper_version: helperVersion,
  previous_version: previousVersion,
  product_label: policy.product_label,
  reason,
  release_train_target: releaseTrainTargetVersion,
  should_release: shouldRelease,
  source_sha: sourceSha,
  stable_baseline_version: stableBaselineVersion,
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
    intent: "",
    output: "",
    publishedReleaseTagsPath: "",
    ref: "",
    sha: "",
    sourceSha: "",
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
      case "--intent":
        parsed.intent = value;
        break;
      case "--output":
        parsed.output = value;
        break;
      case "--published-release-tags":
        parsed.publishedReleaseTagsPath = value;
        break;
      case "--ref":
        parsed.ref = value;
        break;
      case "--sha":
        parsed.sha = value;
        break;
      case "--source-sha":
        parsed.sourceSha = value;
        break;
      case "--version-input":
        parsed.versionInput = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  if (parsed.event === "workflow_dispatch" && parsed.intent === "") {
    parsed.intent = "retry";
  }
  if (
    parsed.event === "push" &&
    (parsed.versionInput !== "" || parsed.sourceSha !== "")
  ) {
    fail("automatic releases cannot declare manual version or source inputs");
  }
  if (
    parsed.event === "" ||
    parsed.ref === "" ||
    parsed.sha === "" ||
    parsed.publishedReleaseTagsPath === ""
  ) {
    fail(
      "usage: derive-release.mjs --event <push|workflow_dispatch> --ref <git-ref> --sha <commit> --published-release-tags <path> [--intent <retry|alpha|beta>] [--source-sha <commit>] [--version-input <retry-version>] [--output <path>]",
    );
  }
  return parsed;
}

async function readPublishedReleaseTags(path) {
  let parsed;
  try {
    parsed = JSON.parse(await readFile(resolve(path), "utf8"));
  } catch {
    fail("published release tags must be a readable JSON array");
  }
  if (!Array.isArray(parsed)) {
    fail("published release tags must be a JSON array");
  }
  const availableTags = new Map(releaseTags().map((entry) => [entry.tag, entry]));
  const published = new Set();
  for (const tag of parsed) {
    if (typeof tag !== "string") {
      fail("published release tag names must be strings");
    }
    const version = tag.startsWith("v") ? parseProductVersion(tag.slice(1)) : null;
    if (version === null) continue;
    if (!availableTags.has(tag)) {
      fail(`published release tag ${tag} is not an available lightweight product tag`);
    }
    if (published.has(tag)) {
      fail(`published release tag ${tag} is duplicated`);
    }
    published.add(tag);
  }
  return published;
}

function requireMainRef(label) {
  if (options.ref !== "refs/heads/main") {
    fail(`${label} must run from refs/heads/main`);
  }
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
  if (result.status !== 0) return null;
  return parseRecord(result.stdout, "previous release manifest");
}

function readRecordAt(commit, path, label) {
  const result = spawnSync("git", ["show", `${commit}:${path}`], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) fail(`cannot read ${label} from release commit`);
  return parseRecord(result.stdout, label);
}

function exactLightweightTagCommit(tag) {
  const reference = `refs/tags/${tag}`;
  const type = spawnSync("git", ["cat-file", "-t", reference], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (type.status !== 0) {
    fail(`manual release retry requires existing immutable tag ${tag}`);
  }
  if (type.stdout.trim() !== "commit") {
    fail(`manual release retry requires ${tag} to be a lightweight commit tag`);
  }
  const commit = spawnSync("git", ["rev-parse", "--verify", reference], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (commit.status !== 0) fail(`cannot resolve immutable release tag ${tag}`);
  return strictCommit(commit.stdout.trim());
}

function requireMissingTag(tag) {
  const result = spawnSync("git", ["show-ref", "--verify", "--quiet", `refs/tags/${tag}`], {
    cwd: repositoryRoot,
    stdio: "ignore",
  });
  if (result.status === 0) {
    fail(`new prerelease tag ${tag} already exists; use intent retry`);
  }
  if (result.status !== 1) fail(`cannot inspect candidate tag ${tag}`);
}

function requireCommit(commit, label) {
  const result = spawnSync("git", ["cat-file", "-e", `${commit}^{commit}`], {
    cwd: repositoryRoot,
    stdio: "ignore",
  });
  if (result.status !== 0) fail(`${label} is not an available Git commit`);
}

function requireSameRepositoryBranch(commit) {
  const result = spawnSync(
    "git",
    [
      "for-each-ref",
      `--contains=${commit}`,
      "--format=%(refname)",
      "refs/heads",
      "refs/remotes/origin",
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status !== 0) fail("cannot inspect same-repository branch refs");
  const branches = result.stdout
    .trim()
    .split("\n")
    .filter(
      (reference) =>
        reference.startsWith("refs/heads/") ||
        (reference.startsWith("refs/remotes/origin/") &&
          reference !== "refs/remotes/origin/HEAD"),
    );
  if (branches.length === 0) {
    fail("alpha source must be reachable from a same-repository branch");
  }
}

function requireReviewedReleasePolicy(reviewed, candidate) {
  if (
    JSON.stringify(reviewed) !== JSON.stringify(candidate) ||
    reviewed.repository !== candidate.repository ||
    reviewed.workflow !== candidate.workflow ||
    releaseTrainTarget(reviewed) !== releaseTrainTarget(candidate) ||
    !validateReleaseChannelContract(reviewed) ||
    !validateReleaseChannelContract(candidate)
  ) {
    fail("candidate release policy differs from the reviewed main policy");
  }
  for (const channel of ["alpha", "beta", "stable"]) {
    const expected = reviewed.release_channels[channel];
    const actual = candidate.release_channels[channel];
    if (
      expected.github_latest !== actual.github_latest ||
      expected.github_prerelease !== actual.github_prerelease ||
      expected.product_label !== actual.product_label
    ) {
      fail("candidate release policy differs from the reviewed main policy");
    }
  }
}

function requireAncestor(
  releaseCommit,
  workflowCommit,
  message = "immutable release tag must be an ancestor of the trusted main workflow",
) {
  const result = spawnSync(
    "git",
    ["merge-base", "--is-ancestor", releaseCommit, workflowCommit],
    { cwd: repositoryRoot, stdio: "ignore" },
  );
  if (result.status !== 0) fail(message);
}

function previousStableReleaseVersion(sourceShaValue, currentVersion) {
  const history = spawnSync(
    "git",
    ["rev-list", "--first-parent", sourceShaValue, "--", ".release-please-manifest.json"],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (history.status !== 0) fail("cannot inspect the tagged release manifest history");
  for (const candidateSha of history.stdout.trim().split("\n").filter(Boolean)) {
    const candidateManifest = readRecordAt(
      strictCommit(candidateSha),
      ".release-please-manifest.json",
      "release transition manifest",
    );
    const candidateVersion = strictStableVersion(
      candidateManifest["."],
      "release transition version",
    );
    if (candidateVersion !== currentVersion) break;
    const previousManifest = readPreviousManifest(candidateSha);
    if (previousManifest === null) continue;
    const previous = strictStableVersion(
      previousManifest["."],
      "previous release manifest version",
    );
    if (previous === currentVersion) continue;
    requireExactFirstPublicVersion(previous, currentVersion);
    if (compareProductVersions(currentVersion, previous) <= 0) {
      fail("manual release retries must select a tag containing a monotonic manifest transition");
    }
    return currentVersion === "0.0.1" ? "" : previous;
  }
  fail("manual release retries must select a tag containing the release manifest transition");
}

function releaseTags() {
  const result = spawnSync(
    "git",
    [
      "for-each-ref",
      "--format=%(objecttype)%09%(objectname)%09%(refname:strip=2)",
      "refs/tags/v*",
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status !== 0) fail("cannot inspect official release tags");
  const tags = [];
  for (const line of result.stdout.trim().split("\n").filter(Boolean)) {
    const [type, commit, tag] = line.split("\t");
    const parsed = tag?.startsWith("v") ? parseProductVersion(tag.slice(1)) : null;
    if (parsed === null) continue;
    if (type !== "commit" || !/^[0-9a-f]{40}$/u.test(commit)) {
      fail(`official release tag ${tag} is not a lightweight commit tag`);
    }
    tags.push({ commit, tag, version: parsed.version });
  }
  return tags;
}

function nextPrereleaseVersion(target, channel) {
  const prefix = `${target}-${channel}.`;
  let sequence = 0;
  for (const { version: candidate } of releaseTags()) {
    const parsed = parseProductVersion(candidate);
    if (
      parsed?.channel !== channel ||
      productVersionCore(candidate) !== target
    ) {
      continue;
    }
    const value = Number(candidate.slice(prefix.length));
    if (!Number.isSafeInteger(value) || value < 1) {
      fail(`official ${channel} tag has an invalid sequence`);
    }
    sequence = Math.max(sequence, value);
  }
  if (sequence === Number.MAX_SAFE_INTEGER) {
    fail(`${channel} release sequence is exhausted`);
  }
  return `${prefix}${sequence + 1}`;
}

function artifactPredecessorVersion(
  sourceShaValue,
  currentVersion,
  publishedReleaseTags,
) {
  const candidates = releaseTags()
    .filter(({ tag }) => publishedReleaseTags.has(tag))
    .filter(({ version: candidate }) => compareProductVersions(candidate, currentVersion) < 0)
    .sort((left, right) => compareProductVersions(right.version, left.version));
  if (candidates.length === 0) return "";
  const predecessor = candidates[0];
  const stablePredecessor = candidates.find(
    ({ version: candidate }) => parseProductVersion(candidate)?.channel === "stable",
  );
  if (stablePredecessor !== undefined) {
    requireAncestor(stablePredecessor.commit, sourceShaValue);
  }
  return predecessor.version;
}

function requireNewVersionAfterAllTags(
  currentVersion,
  sourceShaValue,
  publishedReleaseTags,
) {
  const newest = releaseTags().sort((left, right) =>
    compareProductVersions(right.version, left.version),
  )[0];
  if (newest === undefined) return;
  const previous = parseProductVersion(newest.version);
  const currentCore = productVersionCore(currentVersion);
  const previousCore = productVersionCore(newest.version);
  if (previous.channel !== "stable" && currentCore !== previousCore) {
    fail(
      `release train ${previousCore} must reach stable before starting ${currentCore}`,
    );
  }
  if (
    previous.channel === "stable" &&
    currentCore !== previousCore &&
    !publishedReleaseTags.has(newest.tag)
  ) {
    fail(
      `release train ${previousCore} must publish stable before starting ${currentCore}`,
    );
  }
  const comparison = compareProductVersions(currentVersion, newest.version);
  if (comparison === 0 && newest.commit === sourceShaValue) return;
  if (comparison <= 0) {
    fail(
      `new release ${currentVersion} must be newer than existing official tag ${newest.tag}`,
    );
  }
}

function requireRetryableUnpublishedTag(currentVersion, publishedReleaseTags) {
  const currentTag = `v${currentVersion}`;
  if (publishedReleaseTags.has(currentTag)) {
    fail(`manual release retry requires ${currentTag} to remain unpublished`);
  }
  const newer = releaseTags().find(
    ({ version }) => compareProductVersions(version, currentVersion) > 0,
  );
  if (newer !== undefined) {
    fail(
      `manual release retry for ${currentTag} is stale after newer official tag ${newer.tag}`,
    );
  }
}

function requireExactFirstPublicVersion(previous, current) {
  if (previous === "0.0.0" && current !== "0.0.1") {
    fail("the first public release after the 0.0.0 baseline must be exactly 0.0.1");
  }
}

function helperChanged(
  predecessorVersion,
  currentProductVersion,
  currentHelperVersion,
  currentSourceDigest,
  publishedReleaseTags,
) {
  if (predecessorVersion === "") return true;
  const previous = releaseContractAt(
    predecessorVersion,
    "predecessor release contract",
  );
  const previousHelperVersion = strictStableVersion(
    previous.components?.keychain_helper?.version,
    "predecessor Keychain helper version",
  );
  const previousSourceDigest = strictDigest(
    previous.components?.keychain_helper?.source_digest,
    "predecessor Keychain helper source digest",
  );
  const versionChanged = previousHelperVersion !== currentHelperVersion;
  const sourceChanged = previousSourceDigest !== currentSourceDigest;
  if (versionChanged !== sourceChanged) {
    fail("Keychain helper version and production source digest must change together");
  }
  if (versionChanged) {
    if (compareProductVersions(currentHelperVersion, previousHelperVersion) <= 0) {
      fail("Keychain helper version must increase when its production source changes");
    }
    for (const tag of releaseTags().filter(({ tag }) => publishedReleaseTags.has(tag))) {
      if (compareProductVersions(tag.version, currentProductVersion) >= 0) continue;
      const historical = releaseContractAt(tag.version, `release contract ${tag.tag}`);
      if (historical.components?.keychain_helper?.version === currentHelperVersion) {
        fail(
          `Keychain helper ${currentHelperVersion} was already bound to an earlier release`,
        );
      }
    }
  }
  return versionChanged;
}

function releaseContractAt(version, label) {
  const result = spawnSync(
    "git",
    ["show", `refs/tags/v${version}:scripts/release/release-contract.json`],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.status !== 0) fail(`cannot inspect ${label}`);
  return parseRecord(result.stdout, label);
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

function strictProductVersion(value, label) {
  const parsed = parseProductVersion(value);
  if (parsed === null) {
    fail(`${label} must be stable SemVer or use the exact alpha.N/beta.N form`);
  }
  return parsed.version;
}

function strictStableVersion(value, label) {
  const parsed = parseStableVersion(value);
  if (parsed === null) fail(`${label} must be a stable semantic version`);
  return parsed.version;
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
  if (compareProductVersions(value, "0.0.1") < 0) {
    fail("the first public release is v0.0.1");
  }
}

function fail(message) {
  throw new Error(`release_derivation_failed:${message}`);
}
