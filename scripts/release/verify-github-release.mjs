import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";

import {
  parseProductVersion,
  releaseChannelPolicy,
  validateReleaseChannelContract,
} from "./release-version.mjs";

class RetryableGitHubError extends Error {
  constructor(status) {
    super(`GitHub API transient HTTP ${status}`);
    this.name = "RetryableGitHubError";
  }
}

const options = parseOptions(process.argv.slice(2));
const token = process.env.GITHUB_TOKEN;
if (typeof token !== "string" || token === "") fail("GITHUB_TOKEN is required");
const contract = parseRecord(
  await readFile(resolve(import.meta.dirname, "release-contract.json"), "utf8"),
  "release contract",
);
if (!validateReleaseChannelContract(contract)) fail("release channel contract is invalid");
const channelPolicy = releaseChannelPolicy(contract, options.version);
if (channelPolicy === null || channelPolicy.channel !== options.channel) {
  fail("release version and channel are inconsistent");
}

let release;
const propagationAttempts = 12;
for (let attempt = 1; attempt <= propagationAttempts; attempt += 1) {
  try {
    release = await releaseForState();
  } catch (error) {
    if (!(error instanceof RetryableGitHubError) || attempt === propagationAttempts) {
      throw error;
    }
    release = undefined;
  }
  const stateReady =
    release !== undefined && options.state === "draft"
      ? release.draft === true && release.immutable === false
      : release !== undefined && release.draft === false && release.immutable === true;
  if (
    stateReady &&
    release.assets?.every((asset) => typeof asset.digest === "string")
  ) {
    break;
  }
  if (attempt < propagationAttempts) {
    const delay = Math.min(8_000, 500 * 2 ** (attempt - 1));
    await new Promise((resolveWait) => setTimeout(resolveWait, delay));
  }
}
if (
  release === null ||
  typeof release !== "object" ||
  Array.isArray(release) ||
  release.tag_name !== options.tag ||
  release.prerelease !== channelPolicy.github_prerelease ||
  typeof release.name !== "string" ||
  release.name !== `OneNod ${options.tag} — ${channelPolicy.product_label}` ||
  !Array.isArray(release.assets)
) {
  fail("GitHub Release identity is invalid");
}
if (options.state === "draft") {
  if (release.draft !== true || release.immutable !== false) {
    fail("release must remain mutable only while it is a draft");
  }
} else if (
  release.draft !== false ||
  release.immutable !== true ||
  typeof release.published_at !== "string"
) {
  fail("published Release is not immutable");
}
if (options.state === "published" && channelPolicy.github_latest) {
  const latest = await latestRelease();
  if (latest?.id !== release.id || latest?.tag_name !== options.tag) {
    fail("stable Release is not the repository latest Release");
  }
}

const expectedNames = (await readdir(options.directory)).sort();
const actualNames = release.assets.map(({ name }) => name).sort();
if (JSON.stringify(expectedNames) !== JSON.stringify(actualNames)) {
  fail("GitHub Release assets do not match the locally verified complete set");
}
for (const asset of release.assets) {
  const path = resolve(options.directory, asset.name);
  const info = await lstat(path);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    asset.state !== "uploaded" ||
    asset.size !== info.size ||
    asset.digest !== `sha256:${await sha256(path)}`
  ) {
    fail(`GitHub Release asset verification failed: ${asset.name}`);
  }
}

const tagRef = await githubJSON(
  `https://api.github.com/repos/${options.repository}/git/ref/tags/${encodeURIComponent(options.tag)}`,
);
if (tagRef.object?.type !== "commit" || tagRef.object?.sha !== options.commit) {
  fail("release tag no longer points to the reviewed source commit");
}

process.stdout.write(
  `${JSON.stringify({
    assets: release.assets.length,
    event: "github_release_verified",
    immutable: release.immutable,
    state: options.state,
    tag: options.tag,
  })}\n`,
);

async function githubJSON(url, retryTransient = false) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2026-03-10",
    },
    redirect: "error",
  });
  if (
    retryTransient &&
    (response.status === 404 || response.status === 429 || response.status >= 500)
  ) {
    throw new RetryableGitHubError(response.status);
  }
  if (!response.ok) fail(`GitHub API returned HTTP ${response.status}`);
  return response.json();
}

async function releaseForState() {
  if (options.state === "published") {
    return githubJSON(
      `https://api.github.com/repos/${options.repository}/releases/tags/${options.tag}`,
      true,
    );
  }
  const releases = await githubJSON(
    `https://api.github.com/repos/${options.repository}/releases?per_page=100`,
    true,
  );
  if (!Array.isArray(releases)) fail("GitHub Release list is invalid");
  const matches = releases.filter(
    (candidate) =>
      candidate !== null &&
      typeof candidate === "object" &&
      !Array.isArray(candidate) &&
      candidate.tag_name === options.tag &&
      candidate.draft === true,
  );
  if (matches.length === 0) throw new RetryableGitHubError(404);
  if (matches.length !== 1) fail("GitHub draft Release identity is ambiguous");
  return matches[0];
}

async function latestRelease() {
  for (let attempt = 1; attempt <= propagationAttempts; attempt += 1) {
    try {
      const candidate = await githubJSON(
        `https://api.github.com/repos/${options.repository}/releases/latest`,
        true,
      );
      if (candidate?.tag_name === options.tag) return candidate;
    } catch (error) {
      if (!(error instanceof RetryableGitHubError) || attempt === propagationAttempts) {
        throw error;
      }
    }
    if (attempt < propagationAttempts) {
      const delay = Math.min(8_000, 500 * 2 ** (attempt - 1));
      await new Promise((resolveWait) => setTimeout(resolveWait, delay));
    }
  }
  fail("stable Release did not become the repository latest Release");
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function parseRecord(value, label) {
  try {
    const parsed = JSON.parse(value);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      fail(`${label} is not a JSON object`);
    }
    return parsed;
  } catch (error) {
    if (error instanceof SyntaxError) fail(`${label} is not valid JSON`);
    throw error;
  }
}

function parseOptions(args) {
  const values = {
    channel: "",
    commit: "",
    directory: "",
    repository: "",
    state: "",
    tag: "",
    version: "",
  };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--channel":
        values.channel = value;
        break;
      case "--commit":
        values.commit = value;
        break;
      case "--directory":
        values.directory = resolve(value);
        break;
      case "--repository":
        values.repository = value;
        break;
      case "--state":
        values.state = value;
        break;
      case "--tag":
        values.tag = value;
        break;
      case "--version":
        values.version = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  if (
    values.repository !== "Vizards/OneNod" ||
    values.tag !== `v${values.version}` ||
    parseProductVersion(values.version)?.channel !== values.channel ||
    !/^[0-9a-f]{40}$/u.test(values.commit) ||
    !["draft", "published"].includes(values.state) ||
    values.directory === ""
  ) {
    fail("release verification arguments are invalid");
  }
  return values;
}

function fail(message) {
  throw new Error(`github_release_verification_failed:${message}`);
}
