import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { readArtifactArchive, readArtifactIdentity } from "./artifact-tar.mjs";
import {
  parseProductVersion,
  releaseChannelPolicy,
  releaseMatchesTrain,
  releaseTrainTarget,
  validateReleaseChannelContract,
} from "./release-version.mjs";

const options = parseOptions(process.argv.slice(2));
const releaseContract = parseRecord(
  await readFile(resolve(import.meta.dirname, "release-contract.json"), "utf8"),
  "release contract",
);
if (!validateReleaseChannelContract(releaseContract)) {
  fail("release channel contract is invalid");
}
if (
  releaseTrainTarget(releaseContract) === null ||
  !releaseMatchesTrain(releaseContract, options.version)
) {
  fail("release version differs from the reviewed release train");
}
const channelPolicy = releaseChannelPolicy(releaseContract, options.version);
if (channelPolicy === null) fail("release version has no channel policy");
const manifestPath = resolve(options.directory, "release-manifest.json");
const manifest = parseRecord(await readFile(manifestPath, "utf8"), "release manifest");
validateManifest(manifest, options, channelPolicy);

const helperVersion = manifest.components.keychain_helper.version;
const releaseArchives = [
  "onenod-darwin-arm64.tar.gz",
  "onenod-darwin-amd64.tar.gz",
  `onenod-deployment-${options.version}.tar.gz`,
  `onenod-keychain-helper-${helperVersion}-darwin-arm64.tar.gz`,
  `onenod-keychain-helper-${helperVersion}-darwin-amd64.tar.gz`,
  `onenod-skill-${options.version}.tar.gz`,
];
const artifactSboms = releaseArchives.map((subject) => ({
  name: `${subject.slice(0, -7)}.spdx.json`,
  subject,
}));
const primaryNames = [
  "release-manifest.json",
  "SHA256SUMS",
  "THIRD_PARTY_NOTICES.txt",
  "onenod-darwin-arm64.tar.gz",
  "onenod-darwin-amd64.tar.gz",
  `onenod-deployment-${options.version}.tar.gz`,
  `onenod-keychain-helper-${helperVersion}-darwin-arm64.tar.gz`,
  `onenod-keychain-helper-${helperVersion}-darwin-amd64.tar.gz`,
  `onenod-skill-${options.version}.tar.gz`,
  ...artifactSboms.map(({ name }) => name),
];
const attestationNames = [
  "onenod-provenance.intoto.jsonl",
];
const expectedNames = [
  ...primaryNames,
  ...(options.phase === "complete" ? attestationNames : []),
].sort();
const actualNames = (await readdir(options.directory)).sort();
if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
  fail(
    `release directory does not contain the exact expected set: ${actualNames.join(",")}`,
  );
}

const manifestArtifactNames = manifest.artifacts.map(({ name }) => name);
const expectedManifestArtifactNames = primaryNames.filter(
  (name) => !["release-manifest.json", "SHA256SUMS"].includes(name),
);
if (
  JSON.stringify([...manifestArtifactNames].sort()) !==
  JSON.stringify([...expectedManifestArtifactNames].sort())
) {
  fail("release manifest artifact inventory is incomplete or has unexpected entries");
}
for (const artifact of manifest.artifacts) {
  if (
    artifact === null ||
    typeof artifact !== "object" ||
    typeof artifact.name !== "string" ||
    typeof artifact.kind !== "string" ||
    typeof artifact.size !== "number" ||
    !Number.isSafeInteger(artifact.size) ||
    artifact.size <= 0 ||
    typeof artifact.sha256 !== "string" ||
    !/^sha256:[0-9a-f]{64}$/u.test(artifact.sha256)
  ) {
    fail("release manifest contains an invalid artifact descriptor");
  }
  const path = resolve(options.directory, artifact.name);
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== artifact.size) {
    fail(`artifact size or file type changed: ${artifact.name}`);
  }
  if (`sha256:${await sha256(path)}` !== artifact.sha256) {
    fail(`artifact digest changed: ${artifact.name}`);
  }
  if (artifact.kind === "sbom") {
    const expected = artifactSboms.find(({ name }) => name === artifact.name);
    if (expected === undefined || artifact.subject !== expected.subject) {
      fail(`SBOM manifest subject is invalid: ${artifact.name}`);
    }
  } else if (artifact.subject !== undefined) {
    fail(`non-SBOM artifact unexpectedly has a subject: ${artifact.name}`);
  }
}

const checksums = parseChecksums(
  await readFile(resolve(options.directory, "SHA256SUMS"), "utf8"),
);
const expectedChecksumNames = primaryNames.filter((name) => name !== "SHA256SUMS");
if (
  JSON.stringify([...checksums.keys()].sort()) !==
  JSON.stringify([...expectedChecksumNames].sort())
) {
  fail("SHA256SUMS does not cover the exact primary release set");
}
for (const [name, expectedDigest] of checksums) {
  if ((await sha256(resolve(options.directory, name))) !== expectedDigest) {
    fail(`checksum verification failed: ${name}`);
  }
}

await verifySupportFiles(options);
await verifyArchive(
  resolve(options.directory, "onenod-darwin-arm64.tar.gz"),
  "onenod/",
  [
    "onenod/bin/may",
    "onenod/bin/may-ssh-sign",
    "onenod/LICENSE",
    "onenod/RELEASE.json",
    "onenod/THIRD_PARTY_COMPONENTS.json",
    "onenod/THIRD_PARTY_NOTICES.txt",
  ],
  options,
);
await verifyArchive(
  resolve(options.directory, "onenod-darwin-amd64.tar.gz"),
  "onenod/",
  [
    "onenod/bin/may",
    "onenod/bin/may-ssh-sign",
    "onenod/LICENSE",
    "onenod/RELEASE.json",
    "onenod/THIRD_PARTY_COMPONENTS.json",
    "onenod/THIRD_PARTY_NOTICES.txt",
  ],
  options,
);
for (const arch of ["arm64", "amd64"]) {
  await verifyArchive(
    resolve(
      options.directory,
      `onenod-keychain-helper-${helperVersion}-darwin-${arch}.tar.gz`,
    ),
    "onenod-keychain-helper/",
    [
      "onenod-keychain-helper/bin/onenod-keychain-helper",
      "onenod-keychain-helper/LICENSE",
      "onenod-keychain-helper/RELEASE.json",
      "onenod-keychain-helper/THIRD_PARTY_COMPONENTS.json",
      "onenod-keychain-helper/THIRD_PARTY_NOTICES.txt",
    ],
    options,
  );
}
await verifyArchive(
  resolve(options.directory, `onenod-deployment-${options.version}.tar.gz`),
  "onenod-deployment/",
  [
    "onenod-deployment/gateway/worker.mjs",
    "onenod-deployment/gateway/wrangler.jsonc",
    "onenod-deployment/executor/worker.mjs",
    "onenod-deployment/executor/plugin.wasm",
    "onenod-deployment/executor/wrangler.jsonc",
    "onenod-deployment/deployment.json",
    "onenod-deployment/LICENSE",
    "onenod-deployment/THIRD_PARTY_COMPONENTS.json",
    "onenod-deployment/THIRD_PARTY_NOTICES.txt",
    "onenod-deployment/executor/third-party/onepassword-sdk-go/LICENSE",
    "onenod-deployment/executor/third-party/onepassword-sdk-go/SOURCE.json",
  ],
  options,
);
await verifyArchive(
  resolve(options.directory, `onenod-skill-${options.version}.tar.gz`),
  "onenod-skill/",
  [
    "onenod-skill/onenod/SKILL.md",
    "onenod-skill/LICENSE",
    "onenod-skill/RELEASE.json",
  ],
  options,
);

if (options.phase === "complete") {
  for (const name of attestationNames) {
    await verifyJSONLines(resolve(options.directory, name));
  }
}

process.stdout.write(
  `${JSON.stringify({
    artifacts: manifest.artifacts.length,
    event: "release_set_verified",
    phase: options.phase,
    release_version: options.version,
  })}\n`,
);

function validateManifest(value, values, policy) {
  if (
    value.schema_version !== 1 ||
    value.release_version !== values.version ||
    value.channel !== policy.channel ||
    value.product_label !== policy.product_label ||
    value.tag !== `v${values.version}` ||
    value.source?.repository !== "Vizards/OneNod" ||
    value.source?.workflow !== ".github/workflows/release.yml" ||
    value.source?.commit !== values.commit ||
    value.support?.latest_only !== true ||
    value.support?.minimum_safe_version !== value.upgrade?.minimum_safe_version ||
    JSON.stringify(value.revoked_artifact_digests) !==
      JSON.stringify(value.upgrade?.revoked_artifact_digests) ||
    value.attestations?.repository !== "Vizards/OneNod" ||
    value.attestations?.workflow !== ".github/workflows/release.yml" ||
    !Array.isArray(value.artifacts)
  ) {
    fail("release manifest identity or support policy is invalid");
  }
  for (const component of ["may", "ssh_agent", "gateway", "executor", "pwa", "skill"]) {
    if (value.components?.[component]?.version !== values.version) {
      fail(`component version drift: ${component}`);
    }
  }
  if (
    typeof value.components?.keychain_helper?.source_digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/u.test(
      value.components.keychain_helper.source_digest,
    ) ||
    !Number.isSafeInteger(
      value.components.keychain_helper.helper_protocol?.min,
    ) ||
    !Number.isSafeInteger(
      value.components.keychain_helper.helper_protocol?.max,
    ) ||
    value.components.keychain_helper.helper_protocol.min <= 0 ||
    value.components.keychain_helper.helper_protocol.max <
      value.components.keychain_helper.helper_protocol.min
  ) {
    fail("Keychain helper source identity is invalid");
  }
  if (
    value.requirements?.macos?.minimum !== "15.0" ||
    JSON.stringify(value.requirements?.macos?.architectures) !==
      JSON.stringify(["arm64", "amd64"]) ||
    value.requirements?.node?.minimum !== "22.12.0" ||
    value.requirements?.node?.maximum_exclusive !== "23.0.0" ||
    value.requirements?.wrangler?.minimum !== "4.116.0" ||
    value.requirements?.wrangler?.maximum_exclusive !== "5.0.0" ||
    value.requirements?.onepassword_cli?.minimum !== "2.34.0" ||
    value.requirements?.onepassword_cli?.maximum_exclusive !== "3.0.0"
  ) {
    fail("release compatibility requirements are invalid");
  }
}

async function verifySupportFiles(values) {
  const notices = await readFile(
    resolve(values.directory, "THIRD_PARTY_NOTICES.txt"),
    "utf8",
  );
  if (
    !notices.includes("Format: 2") ||
    !notices.includes(`Release: ${values.version}`) ||
    !notices.includes(`Source commit: ${values.commit}`) ||
    !notices.includes("Scope: release") ||
    !/Component inventory SHA-256: [0-9a-f]{64}/u.test(notices) ||
    !notices.includes("Go standard library and runtime") ||
    !notices.includes("Copyright (c) 2024 1Password") ||
    !notices.includes(
      "Original SHA-256: 23d115f4ac7519b48172df3e8615945572dbda7033d51b44c9490fd533ae0f23",
    ) ||
    !notices.includes(
      "Processed SHA-256: 803c7752dd41abc3911a75ac2df9b83197d000265d42d6412760458ba07858f6",
    ) ||
    /\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(notices)
  ) {
    fail("third-party notices are incomplete or not bound to this release");
  }
  for (const { name, subject } of artifactSboms) {
    const sbom = parseRecord(
      await readFile(resolve(values.directory, name), "utf8"),
      `${subject} SPDX SBOM`,
    );
    await verifyArtifactSBOM(sbom, resolve(values.directory, subject), subject, values);
    const content = JSON.stringify(sbom);
    if (/\/(?:Users|home\/runner)\//u.test(content)) {
      fail("support artifacts contain an absolute workstation path");
    }
  }
  if (/\/(?:Users|home\/runner)\//u.test(notices)) {
    fail("support artifacts contain an absolute workstation path");
  }
}

async function verifyArtifactSBOM(sbom, archivePath, subject, values) {
  if (
    typeof sbom.spdxVersion !== "string" ||
    !sbom.spdxVersion.startsWith("SPDX-") ||
    sbom.name !== subject ||
    !Array.isArray(sbom.packages) ||
    !Array.isArray(sbom.files) ||
    !Array.isArray(sbom.relationships) ||
    !Array.isArray(sbom.documentDescribes) ||
    sbom.documentDescribes.length !== 1
  ) {
    fail(`artifact SPDX SBOM is missing required metadata: ${subject}`);
  }
  const archive = await readArtifactArchive(archivePath);
  const identity = readArtifactIdentity(archive.files);
  validateArtifactIdentity(identity, subject);
  if (
    identity.kind !== "keychain_helper" &&
    (identity.version !== values.version || identity.sourceCommit !== values.commit)
  ) {
    fail(`artifact identity differs from the current release: ${subject}`);
  }
  const root = sbom.packages.find(
    ({ SPDXID }) => SPDXID === sbom.documentDescribes[0],
  );
  if (
    root === undefined ||
    root.name !== subject ||
    root.versionInfo !== identity.version ||
    !Array.isArray(root.checksums) ||
    !root.checksums.some(
      ({ algorithm, checksumValue }) =>
        algorithm === "SHA256" && checksumValue === archive.archiveSha256,
    )
  ) {
    fail(`artifact SPDX SBOM is not bound to archive bytes: ${subject}`);
  }
  const sbomFiles = new Map();
  for (const file of sbom.files) {
    if (typeof file.fileName !== "string" || sbomFiles.has(file.fileName)) {
      fail(`artifact SPDX SBOM has an invalid file inventory: ${subject}`);
    }
    const digest = Array.isArray(file.checksums)
      ? file.checksums.find(({ algorithm }) => algorithm === "SHA256")?.checksumValue
      : undefined;
    sbomFiles.set(file.fileName, digest);
  }
  if (
    JSON.stringify([...sbomFiles.keys()].sort()) !==
    JSON.stringify([...archive.files.keys()].sort())
  ) {
    fail(`artifact SPDX SBOM file coverage is incomplete: ${subject}`);
  }
  for (const [name, descriptor] of archive.files) {
    if (sbomFiles.get(name) !== descriptor.sha256) {
      fail(`artifact SPDX SBOM file digest changed: ${subject}:${name}`);
    }
  }
  const inventoryEntry = [...archive.files.entries()].find(([name]) =>
    name.endsWith("/THIRD_PARTY_COMPONENTS.json"),
  );
  if (inventoryEntry !== undefined) {
    const inventory = parseRecord(
      inventoryEntry[1].content.toString("utf8"),
      `${subject} third-party inventory`,
    );
    validateComponentInventory(inventory, identity, subject);
    for (const component of inventory.components) {
      const dependency = sbom.packages.find(
        ({ name, versionInfo, licenseDeclared }) =>
          name === component.name &&
          versionInfo === component.version &&
          licenseDeclared === component.license,
      );
      if (
        dependency === undefined ||
        !sbom.relationships.some(
          ({ spdxElementId, relatedSpdxElement, relationshipType }) =>
            spdxElementId === root.SPDXID &&
            relatedSpdxElement === dependency.SPDXID &&
            relationshipType === "DEPENDS_ON",
        )
      ) {
        fail(`artifact SPDX SBOM omits ${component.name}@${component.version}`);
      }
    }
  }
}

async function verifyArchive(path, expectedRoot, requiredEntries, values) {
  const result = spawnSync("tar", ["-tzf", path], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) fail(`cannot inspect release archive ${path}`);
  const entries = result.stdout.split("\n").filter((entry) => entry !== "");
  if (entries.length === 0) fail(`release archive is empty: ${path}`);
  for (const entry of entries) {
    if (
      !entry.startsWith(expectedRoot) ||
      entry.startsWith("/") ||
      entry.split("/").includes("..") ||
      /(?:^|\/)(?:\.DS_Store|\.private|node_modules)(?:\/|$)/u.test(entry) ||
      entry.endsWith(".map")
    ) {
      fail(`unsafe or unexpected release archive entry: ${entry}`);
    }
  }
  for (const required of requiredEntries) {
    if (!entries.includes(required)) fail(`release archive is missing ${required}`);
  }
  const archive = await readArtifactArchive(path);
  const identity = readArtifactIdentity(archive.files);
  validateArtifactIdentity(identity, path);
  if (
    identity.kind !== "keychain_helper" &&
    (identity.version !== values.version || identity.sourceCommit !== values.commit)
  ) {
    fail(`archive identity differs from the current release: ${path}`);
  }
  const coreSource = archive.files.get(
    "onenod-deployment/executor/third-party/onepassword-sdk-go/SOURCE.json",
  );
  if (coreSource !== undefined) {
    const evidence = parseRecord(
      coreSource.content.toString("utf8"),
      "packaged 1Password core source evidence",
    );
    const coreLicense = archive.files.get(
      "onenod-deployment/executor/third-party/onepassword-sdk-go/LICENSE",
    );
    const plugin = archive.files.get("onenod-deployment/executor/plugin.wasm");
    if (
      coreLicense === undefined ||
      plugin === undefined ||
      evidence.repository !== "https://github.com/1Password/onepassword-sdk-go" ||
      evidence.sourceTag !== "v0.4.1" ||
      evidence.license !== "MIT" ||
      evidence.copyright !== "Copyright (c) 2024 1Password" ||
      evidence.originalSha256 !==
        "23d115f4ac7519b48172df3e8615945572dbda7033d51b44c9490fd533ae0f23" ||
      evidence.processedSha256 !== plugin.sha256 ||
      evidence.licenseSha256 !== coreLicense.sha256 ||
      !coreLicense.content.toString("utf8").includes(evidence.copyright)
    ) {
      fail("deployment archive has invalid third-party source attribution");
    }
  }
  const noticesEntry = [...archive.files.entries()].find(([name]) =>
    name.endsWith("/THIRD_PARTY_NOTICES.txt"),
  );
  const inventoryEntry = [...archive.files.entries()].find(([name]) =>
    name.endsWith("/THIRD_PARTY_COMPONENTS.json"),
  );
  if (noticesEntry !== undefined || inventoryEntry !== undefined) {
    if (noticesEntry === undefined || inventoryEntry === undefined) {
      fail("third-party notices and component inventory must be packaged together");
    }
    const notices = noticesEntry[1].content.toString("utf8");
    const inventory = parseRecord(
      inventoryEntry[1].content.toString("utf8"),
      "archive component inventory",
    );
    const componentDigest = createHash("sha256")
      .update(JSON.stringify(inventory.components))
      .digest("hex");
    if (
      !notices.includes("Format: 2") ||
      !notices.includes(`Release: ${identity.version}`) ||
      !notices.includes(`Source commit: ${identity.sourceCommit}`) ||
      !notices.includes(`Components: ${inventory.components.length}`) ||
      !notices.includes(`Component inventory SHA-256: ${componentDigest}`) ||
      /\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(notices)
    ) {
      fail(`archive has incomplete third-party notices: ${path}`);
    }
    validateComponentInventory(
      inventory,
      identity,
      path,
    );
  }
}

function validateArtifactIdentity(identity, label) {
  if (identity.kind !== "keychain_helper") return;
  const helper = manifest.components.keychain_helper;
  if (
    identity.version !== helper.version ||
    identity.helperSourceDigest !== helper.source_digest ||
    identity.helperProtocol < helper.helper_protocol.min ||
    identity.helperProtocol > helper.helper_protocol.max
  ) {
    fail(`Keychain helper identity differs from the release manifest: ${label}`);
  }
}

function validateComponentInventory(value, identity, label) {
  if (
    value.schema_version !== 1 ||
    value.release_version !== identity.version ||
    value.source_commit !== identity.sourceCommit ||
    !Array.isArray(value.components)
  ) {
    fail(`third-party component inventory is invalid: ${label}`);
  }
  const keys = new Set();
  for (const component of value.components) {
    if (
      component === null ||
      typeof component !== "object" ||
      typeof component.name !== "string" ||
      typeof component.version !== "string" ||
      typeof component.license !== "string" ||
      typeof component.source !== "string" ||
      /\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(component.license)
    ) {
      fail(`third-party component inventory has an unresolved entry: ${label}`);
    }
    const key = `${component.name}\u0000${component.version}`;
    if (keys.has(key)) fail(`third-party component inventory repeats ${key}`);
    keys.add(key);
  }
}

function parseChecksums(value) {
  if (!value.endsWith("\n")) fail("SHA256SUMS must end with a newline");
  const parsed = new Map();
  for (const line of value.trimEnd().split("\n")) {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$/u.exec(line);
    if (match === null || parsed.has(match[2])) fail("SHA256SUMS is malformed");
    parsed.set(match[2], match[1]);
  }
  return parsed;
}

async function verifyJSONLines(path) {
  const content = await readFile(path, "utf8");
  if (content.trim() === "") fail(`attestation bundle is empty: ${path}`);
  try {
    JSON.parse(content);
    return;
  } catch {
    for (const line of content.trim().split("\n")) {
      JSON.parse(line);
    }
  }
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
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

function parseOptions(args) {
  const values = { commit: "", directory: "", phase: "", version: "" };
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
      case "--phase":
        values.phase = value;
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
  if (parseProductVersion(values.version) === null) {
    fail("release version must be stable SemVer or use the exact alpha.N/beta.N form");
  }
  if (values.directory === "" || !["assembled", "complete"].includes(values.phase)) {
    fail("release directory and verification phase are required");
  }
  return values;
}

function fail(message) {
  throw new Error(`release_set_verification_failed:${message}`);
}
