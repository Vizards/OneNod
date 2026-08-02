import { createHash } from "node:crypto";
import { readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { readArtifactArchive, readArtifactIdentity } from "./artifact-tar.mjs";
import { parseProductVersion } from "./release-version.mjs";

const options = parseOptions(process.argv.slice(2));
const archiveNames = (await readdir(options.directory))
  .filter((name) => name.endsWith(".tar.gz"))
  .sort((left, right) => left.localeCompare(right, "en"));
if (archiveNames.length !== 6) fail("release notice merge requires the six final archives");

const componentsByKey = new Map();
const noticeBundles = new Map();
let applicableArchives = 0;
for (const archiveName of archiveNames) {
  const archive = await readArtifactArchive(resolve(options.directory, archiveName));
  const identity = readArtifactIdentity(archive.files);
  if (
    identity.kind !== "keychain_helper" &&
    (identity.version !== options.version || identity.sourceCommit !== options.commit)
  ) {
    fail(`${archiveName} identity differs from the current release`);
  }
  const noticesEntry = findSuffix(archive.files, "/THIRD_PARTY_NOTICES.txt");
  const inventoryEntry = findSuffix(archive.files, "/THIRD_PARTY_COMPONENTS.json");
  if (noticesEntry === undefined && inventoryEntry === undefined) continue;
  if (noticesEntry === undefined || inventoryEntry === undefined) {
    fail(`${archiveName} carries an incomplete compliance pair`);
  }
  applicableArchives += 1;
  const inventory = parseRecord(
    inventoryEntry.content.toString("utf8"),
    `${archiveName} component inventory`,
  );
  validateInventory(inventory, identity, archiveName);
  const componentDigest = sha256(Buffer.from(JSON.stringify(inventory.components)));
  const notices = noticesEntry.content.toString("utf8");
  if (
    !notices.includes("Format: 2") ||
    !notices.includes(`Release: ${identity.version}`) ||
    !notices.includes(`Source commit: ${identity.sourceCommit}`) ||
    !notices.includes(`Components: ${inventory.components.length}`) ||
    !notices.includes(`Component inventory SHA-256: ${componentDigest}`) ||
    /\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(notices)
  ) {
    fail(`${archiveName} notices are unresolved or differ from its inventory`);
  }
  for (const component of inventory.components) {
    const key = componentKey(component);
    const encoded = JSON.stringify(component);
    const previous = componentsByKey.get(key);
    if (previous !== undefined && previous !== encoded) {
      fail(`third-party component metadata differs across archives: ${key}`);
    }
    componentsByKey.set(key, encoded);
  }
  const noticeDigest = sha256(noticesEntry.content);
  const bundle = noticeBundles.get(noticeDigest);
  if (bundle === undefined) {
    noticeBundles.set(noticeDigest, { content: notices.trimEnd(), subjects: [archiveName] });
  } else {
    bundle.subjects.push(archiveName);
  }
}
if (applicableArchives !== 5) {
  fail("all native and deployment archives must carry license material; Skill must not duplicate it");
}

const components = [...componentsByKey.values()]
  .map((value) => JSON.parse(value))
  .sort((left, right) => componentKey(left).localeCompare(componentKey(right), "en"));
const lines = [
  "OneNod Third-Party Notices",
  "==========================",
  "",
  "Format: 2",
  `Release: ${options.version}`,
  `Source commit: ${options.commit}`,
  "Scope: release",
  `Components: ${components.length}`,
  `Component inventory SHA-256: ${sha256(Buffer.from(JSON.stringify(components)))}`,
  "",
  "This release-level file is assembled only from the compliance material",
  "embedded in the six final installable archives. Duplicate byte-identical",
  "notice bundles are carried once and list every archive to which they apply.",
  "",
];
for (const [digest, bundle] of [...noticeBundles.entries()].sort()) {
  lines.push(`--- BEGIN ARTIFACT NOTICES sha256:${digest} ---`);
  lines.push(`Subjects: ${bundle.subjects.sort().join(", ")}`, "", bundle.content);
  lines.push(`--- END ARTIFACT NOTICES sha256:${digest} ---`, "");
}
const output = `${lines.join("\n").trimEnd()}\n`;
if (/\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(output)) {
  fail("merged release notices contain an unresolved license state");
}
await writeFile(options.output, output, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});
process.stdout.write(
  `${JSON.stringify({
    applicable_archives: applicableArchives,
    components: components.length,
    notice_bundles: noticeBundles.size,
    output: options.output,
  })}\n`,
);

function findSuffix(files, suffix) {
  const matches = [...files.entries()].filter(([name]) => name.endsWith(suffix));
  if (matches.length > 1) fail(`archive repeats ${suffix}`);
  return matches[0]?.[1];
}

function validateInventory(value, identity, label) {
  if (
    value.schema_version !== 1 ||
    value.release_version !== identity.version ||
    value.source_commit !== identity.sourceCommit ||
    !Array.isArray(value.components)
  ) {
    fail(`${label} is not bound to this release`);
  }
  const keys = new Set();
  for (const component of value.components) {
    if (
      component === null ||
      typeof component !== "object" ||
      typeof component.ecosystem !== "string" ||
      typeof component.name !== "string" ||
      typeof component.version !== "string" ||
      typeof component.license !== "string" ||
      typeof component.source !== "string" ||
      /\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(component.license)
    ) {
      fail(`${label} contains an unresolved component`);
    }
    const key = componentKey(component);
    if (keys.has(key)) fail(`${label} repeats ${key}`);
    keys.add(key);
  }
}

function componentKey(value) {
  return `${value.ecosystem}\u0000${value.name}\u0000${value.version}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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
  const values = { commit: "", directory: "", output: "", version: "" };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--commit":
        values.commit = value;
        break;
      case "--directory":
        values.directory = resolve(value);
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
  if (
    values.directory === "" ||
    values.output === "" ||
    !/^[0-9a-f]{40}$/u.test(values.commit) ||
    parseProductVersion(values.version) === null
  ) {
    fail("directory, output, version, and source commit are required");
  }
  return values;
}

function fail(message) {
  throw new Error(`release_notice_merge_failed:${message}`);
}
