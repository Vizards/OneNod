import { createHash } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const options = parseOptions(process.argv.slice(2));
const contract = parseRecord(
  await readFile(resolve(import.meta.dirname, "release-contract.json"), "utf8"),
  "release contract",
);
validateContract(contract, options);

const helperVersion = contract.components.keychain_helper.version;
const releaseArchives = [
  "onenod-darwin-arm64.tar.gz",
  "onenod-darwin-amd64.tar.gz",
  `onenod-deployment-${options.version}.tar.gz`,
  `onenod-keychain-helper-${helperVersion}-darwin-arm64.tar.gz`,
  `onenod-keychain-helper-${helperVersion}-darwin-amd64.tar.gz`,
  `onenod-skill-${options.version}.tar.gz`,
];
const expectedArtifacts = [
  {
    kind: "local",
    name: "onenod-darwin-arm64.tar.gz",
    platform: { architecture: "arm64", os: "darwin" },
  },
  {
    kind: "local",
    name: "onenod-darwin-amd64.tar.gz",
    platform: { architecture: "amd64", os: "darwin" },
  },
  {
    kind: "deployment",
    name: `onenod-deployment-${options.version}.tar.gz`,
  },
  {
    kind: "skill",
    name: `onenod-skill-${options.version}.tar.gz`,
  },
  {
    kind: "keychain_helper",
    name: `onenod-keychain-helper-${helperVersion}-darwin-arm64.tar.gz`,
    platform: { architecture: "arm64", os: "darwin" },
  },
  {
    kind: "keychain_helper",
    name: `onenod-keychain-helper-${helperVersion}-darwin-amd64.tar.gz`,
    platform: { architecture: "amd64", os: "darwin" },
  },
  ...releaseArchives.map((subject) => ({
    kind: "sbom",
    name: sbomName(subject),
    subject,
  })),
  {
    kind: "notices",
    name: "THIRD_PARTY_NOTICES.txt",
  },
];

const artifacts = [];
for (const expected of expectedArtifacts) {
  const path = resolve(options.directory, expected.name);
  const info = await lstat(path).catch(() => null);
  if (
    info === null ||
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.size <= 0
  ) {
    fail(`required release artifact is missing or empty: ${expected.name}`);
  }
  artifacts.push({
    kind: expected.kind,
    name: expected.name,
    ...(expected.subject === undefined ? {} : { subject: expected.subject }),
    ...(expected.platform === undefined ? {} : { platform: expected.platform }),
    sha256: `sha256:${await sha256(path)}`,
    size: info.size,
  });
}

const manifest = {
  schema_version: contract.schema_version,
  release_version: options.version,
  channel: contract.channel,
  product_label: contract.product_label,
  tag: `v${options.version}`,
  published_at: options.publishedAt,
  source: {
    repository: contract.repository,
    commit: options.commit,
    workflow: contract.workflow,
  },
  support: {
    latest_only: true,
    minimum_safe_version: contract.upgrade.minimum_safe_version,
    previous_release_version: options.previousVersion,
  },
  revoked_artifact_digests: contract.upgrade.revoked_artifact_digests,
  components: {
    may: {
      version: options.version,
      client_protocol: contract.components.may.client_protocol,
    },
    ssh_agent: { version: options.version },
    keychain_helper: contract.components.keychain_helper,
    gateway: {
      version: options.version,
      accepted_client_protocol:
        contract.components.gateway.accepted_client_protocol,
      state_schema: contract.components.gateway.state_schema,
    },
    executor: {
      version: options.version,
      accepted_gateway_protocol:
        contract.components.executor.accepted_gateway_protocol,
      state_schema: contract.components.executor.state_schema,
    },
    pwa: { version: options.version },
    skill: { version: options.version },
  },
  upgrade: contract.upgrade,
  requirements: contract.requirements,
  attestations: {
    issuer: "https://token.actions.githubusercontent.com",
    repository: contract.repository,
    workflow: contract.workflow,
  },
  artifacts,
};

const manifestPath = resolve(options.directory, "release-manifest.json");
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});

function sbomName(archiveName) {
  if (!archiveName.endsWith(".tar.gz")) {
    throw new Error(`release_manifest_failed:SBOM subject is not an archive: ${archiveName}`);
  }
  return `${archiveName.slice(0, -7)}.spdx.json`;
}

const checksumSubjects = ["release-manifest.json", ...artifacts.map(({ name }) => name)];
const checksumLines = [];
for (const name of checksumSubjects) {
  checksumLines.push(`${await sha256(resolve(options.directory, name))}  ${name}`);
}
await writeFile(
  resolve(options.directory, "SHA256SUMS"),
  `${checksumLines.join("\n")}\n`,
  { encoding: "utf8", flag: "wx", mode: 0o644 },
);

process.stdout.write(
  `${JSON.stringify({
    artifacts: artifacts.length,
    manifest: manifestPath,
    release_version: options.version,
  })}\n`,
);

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function validateContract(value, values) {
  if (
    value.schema_version !== 1 ||
    value.repository !== "Vizards/OneNod" ||
    value.workflow !== ".github/workflows/release.yml" ||
    value.channel !== "stable" ||
    value.product_label !== "Public Preview"
  ) {
    fail("release contract identity is invalid");
  }
  const componentVersions = [
    value.components?.keychain_helper?.version,
    value.upgrade?.minimum_updater_version,
    value.upgrade?.minimum_safe_version,
  ];
  for (const componentVersion of componentVersions) {
    strictVersion(componentVersion, "release contract version");
  }
  if (
    typeof value.components?.keychain_helper?.source_digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/u.test(
      value.components.keychain_helper.source_digest,
    )
  ) {
    fail("Keychain helper source digest is invalid");
  }
  if (compareVersions(value.upgrade.minimum_safe_version, values.version) > 0) {
    fail("minimum safe version cannot exceed the published release");
  }
  if (
    !Array.isArray(value.upgrade.revoked_artifact_digests) ||
    value.upgrade.revoked_artifact_digests.some(
      (digest) => typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(digest),
    )
  ) {
    fail("revoked artifact digests are invalid");
  }
  if (values.version === "0.0.1" && values.previousVersion !== "") {
    fail("v0.0.1 must not claim a previous public release");
  }
  if (values.version !== "0.0.1") {
    strictVersion(values.previousVersion, "previous release version");
    if (compareVersions(values.previousVersion, values.version) >= 0) {
      fail("previous release version must be older than this release");
    }
  }
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
  const values = {
    commit: "",
    directory: "",
    previousVersion: "",
    publishedAt: new Date().toISOString(),
    version: "",
  };
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
      case "--previous-version":
        values.previousVersion = value;
        break;
      case "--published-at":
        values.publishedAt = value;
        break;
      case "--version":
        values.version = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  strictVersion(values.version, "release version");
  if (!/^[0-9a-f]{40}$/u.test(values.commit)) {
    fail("source commit must be a full lowercase Git SHA");
  }
  if (values.directory === "") fail("release directory is required");
  const parsedDate = new Date(values.publishedAt);
  if (
    Number.isNaN(parsedDate.getTime()) ||
    parsedDate.toISOString() !== values.publishedAt
  ) {
    fail("published-at must be a normalized UTC timestamp");
  }
  return values;
}

function strictVersion(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(value)) {
    fail(`${label} must be a stable semantic version`);
  }
  return value;
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
  throw new Error(`release_manifest_failed:${message}`);
}
