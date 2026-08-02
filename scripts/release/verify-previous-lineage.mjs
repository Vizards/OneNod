import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

import { parseProductVersion } from "./release-version.mjs";

const options = parseOptions(process.argv.slice(2));
const releaseBytes = await readFile(options.release);
const manifestBytes = await readFile(options.manifest);
const release = parseRecord(releaseBytes, "previous GitHub Release");
const manifest = parseRecord(manifestBytes, "previous release manifest");
const expectedTag = `v${options.version}`;
const expectedChannel = parseProductVersion(options.version).channel;
const expectedPrerelease = expectedChannel !== "stable";

if (
  release.draft !== false ||
  release.prerelease !== expectedPrerelease ||
  release.immutable !== true ||
  release.tag_name !== expectedTag ||
  !Number.isSafeInteger(release.id) ||
  release.id <= 0 ||
  typeof release.published_at !== "string" ||
  !Array.isArray(release.assets)
) {
  fail("the preceding GitHub Release is not published, correctly classified, and immutable");
}

const manifestAssets = release.assets.filter(
  (asset) => asset?.name === "release-manifest.json",
);
if (manifestAssets.length !== 1) {
  fail("the preceding GitHub Release does not have exactly one release manifest");
}
const manifestAsset = manifestAssets[0];
const manifestInfo = await stat(options.manifest);
const manifestDigest = `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`;
if (
  manifestAsset.state !== "uploaded" ||
  manifestAsset.size !== manifestInfo.size ||
  manifestAsset.digest !== manifestDigest
) {
  fail("the downloaded preceding release manifest differs from immutable asset metadata");
}

if (
  manifest.schema_version !== 1 ||
  manifest.release_version !== options.version ||
  manifest.tag !== expectedTag ||
  manifest.channel !== expectedChannel ||
  manifest.source?.repository !== "Vizards/OneNod" ||
  manifest.source?.workflow !== ".github/workflows/release.yml" ||
  manifest.source?.commit !== options.commit
) {
  fail("the preceding release manifest is not bound to its canonical tag commit");
}

process.stdout.write(
  `${JSON.stringify({
    commit: options.commit,
    event: "previous_release_lineage_verified",
    release_id: release.id,
    version: options.version,
  })}\n`,
);

function parseOptions(args) {
  const values = { commit: "", manifest: "", release: "", version: "" };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--commit":
        values.commit = value;
        break;
      case "--manifest":
        values.manifest = resolve(value);
        break;
      case "--release":
        values.release = resolve(value);
        break;
      case "--version":
        values.version = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  if (
    !/^[0-9a-f]{40}$/u.test(values.commit) ||
    parseProductVersion(values.version) === null ||
    values.manifest === "" ||
    values.release === ""
  ) {
    fail("previous release lineage arguments are invalid");
  }
  return values;
}

function parseRecord(bytes, label) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${label} is not valid JSON`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail(`${label} must be a JSON object`);
  }
  return parsed;
}

function fail(message) {
  throw new Error(`previous_release_lineage_failed:${message}`);
}
