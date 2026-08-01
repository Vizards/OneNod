import { createHash } from "node:crypto";
import { basename, resolve } from "node:path";
import { readFile, writeFile } from "node:fs/promises";

import { readArtifactArchive, readArtifactIdentity } from "./artifact-tar.mjs";

const options = parseOptions(process.argv.slice(2));
const archiveName = basename(options.archive);
const archive = await readArtifactArchive(options.archive);
const identity = readArtifactIdentity(archive.files);
if (
  identity.kind !== "keychain_helper" &&
  (identity.version !== options.version || identity.sourceCommit !== options.commit)
) {
  fail("final archive identity differs from the current release");
}
const sbom = parseRecord(await readFile(options.sbom, "utf8"), "Syft SPDX SBOM");
if (
  typeof sbom.spdxVersion !== "string" ||
  !sbom.spdxVersion.startsWith("SPDX-") ||
  !Array.isArray(sbom.packages) ||
  !Array.isArray(sbom.relationships)
) {
  fail("Syft output is missing SPDX package metadata");
}

const describedID = Array.isArray(sbom.documentDescribes)
  ? sbom.documentDescribes[0]
  : "";
let artifactPackage = sbom.packages.find(({ SPDXID }) => SPDXID === describedID);
if (artifactPackage === undefined) {
  artifactPackage = sbom.packages.find(({ name }) => name === archiveName);
}
if (artifactPackage === undefined || typeof artifactPackage.SPDXID !== "string") {
  fail("Syft output has no package representing the scanned archive");
}

sbom.name = archiveName;
sbom.documentDescribes = [artifactPackage.SPDXID];
artifactPackage.name = archiveName;
artifactPackage.versionInfo = identity.version;
artifactPackage.filesAnalyzed = true;
artifactPackage.packageVerificationCode = {
  packageVerificationCodeValue: createHash("sha1")
    .update(
      [...archive.files.values()]
        .map(({ sha1 }) => sha1)
        .sort()
        .join(""),
    )
    .digest("hex"),
};
artifactPackage.checksums = [
  { algorithm: "SHA256", checksumValue: archive.archiveSha256 },
];

const files = [];
const fileIDs = new Set();
for (const [name, descriptor] of [...archive.files.entries()].sort()) {
  const id = `SPDXRef-File-${hash(`${name}\u0000${descriptor.sha256}`).slice(0, 24)}`;
  if (fileIDs.has(id)) fail("archive files produced a truncated SPDX ID collision");
  fileIDs.add(id);
  files.push({
    SPDXID: id,
    checksums: [
      { algorithm: "SHA1", checksumValue: descriptor.sha1 },
      { algorithm: "SHA256", checksumValue: descriptor.sha256 },
    ],
    copyrightText: "NOASSERTION",
    fileName: name,
    fileTypes: inferFileTypes(name),
    licenseConcluded: "NOASSERTION",
    licenseInfoInFiles: ["NOASSERTION"],
  });
}
sbom.files = files;
sbom.relationships = sbom.relationships.filter(
  ({ spdxElementId, relatedSpdxElement }) =>
    !String(spdxElementId).startsWith("SPDXRef-File-") &&
    !String(relatedSpdxElement).startsWith("SPDXRef-File-"),
);
for (const file of files) {
  sbom.relationships.push({
    relatedSpdxElement: file.SPDXID,
    relationshipType: "CONTAINS",
    spdxElementId: artifactPackage.SPDXID,
  });
}

const componentEntry = [...archive.files.entries()].find(([name]) =>
  name.endsWith("/THIRD_PARTY_COMPONENTS.json"),
);
let componentCount = 0;
if (componentEntry !== undefined) {
  const inventory = parseRecord(
    componentEntry[1].content.toString("utf8"),
    "artifact third-party component inventory",
  );
  validateInventory(inventory, identity);
  componentCount = inventory.components.length;
  const existing = new Map(
    sbom.packages.map((entry) => [packageKey(entry.name, entry.versionInfo), entry]),
  );
  for (const component of inventory.components) {
    const key = packageKey(component.name, component.version);
    let dependency = existing.get(key);
    if (dependency === undefined) {
      dependency = {
        SPDXID: `SPDXRef-Package-${hash(key).slice(0, 24)}`,
        copyrightText: "NOASSERTION",
        downloadLocation: component.source,
        filesAnalyzed: false,
        licenseConcluded: component.license,
        licenseDeclared: component.license,
        name: component.name,
        versionInfo: component.version,
        ...(typeof component.purl === "string"
          ? {
              externalRefs: [
                {
                  referenceCategory: "PACKAGE-MANAGER",
                  referenceLocator: component.purl,
                  referenceType: "purl",
                },
              ],
            }
          : {}),
      };
      sbom.packages.push(dependency);
      existing.set(key, dependency);
    } else {
      dependency.licenseConcluded = component.license;
      dependency.licenseDeclared = component.license;
    }
    if (
      !sbom.relationships.some(
        ({ spdxElementId, relatedSpdxElement, relationshipType }) =>
          spdxElementId === artifactPackage.SPDXID &&
          relatedSpdxElement === dependency.SPDXID &&
          relationshipType === "DEPENDS_ON",
      )
    ) {
      sbom.relationships.push({
        relatedSpdxElement: dependency.SPDXID,
        relationshipType: "DEPENDS_ON",
        spdxElementId: artifactPackage.SPDXID,
      });
    }
  }
}

sbom.packages.sort((left, right) =>
  packageKey(left.name, left.versionInfo).localeCompare(
    packageKey(right.name, right.versionInfo),
    "en",
  ),
);
sbom.relationships.sort((left, right) =>
  `${left.spdxElementId}\u0000${left.relationshipType}\u0000${left.relatedSpdxElement}`.localeCompare(
    `${right.spdxElementId}\u0000${right.relationshipType}\u0000${right.relatedSpdxElement}`,
    "en",
  ),
);

await writeFile(options.output, `${JSON.stringify(sbom, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});
process.stdout.write(
  `${JSON.stringify({
    archive: archiveName,
    components: componentCount,
    files: files.length,
    output: options.output,
    packages: sbom.packages.length,
  })}\n`,
);

function validateInventory(value, identity) {
  if (
    value.schema_version !== 1 ||
    value.release_version !== identity.version ||
    value.source_commit !== identity.sourceCommit ||
    !Array.isArray(value.components)
  ) {
    fail("artifact component inventory is not bound to this release");
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
      /\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(
        component.license,
      )
    ) {
      fail("artifact component inventory contains an unresolved component");
    }
    const key = packageKey(component.name, component.version);
    if (keys.has(key)) fail(`artifact component inventory repeats ${key}`);
    keys.add(key);
  }
}

function inferFileTypes(name) {
  if (name.endsWith(".wasm")) return ["BINARY"];
  if (/\/(?:may|may-ssh-sign|onenod-keychain-helper)$/u.test(name)) {
    return ["APPLICATION", "BINARY"];
  }
  return ["TEXT"];
}

function packageKey(name, version) {
  return `${String(name)}\u0000${String(version ?? "")}`;
}

function hash(value) {
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
  const values = { archive: "", commit: "", output: "", sbom: "", version: "" };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--archive":
        values.archive = resolve(value);
        break;
      case "--commit":
        values.commit = value;
        break;
      case "--output":
        values.output = resolve(value);
        break;
      case "--sbom":
        values.sbom = resolve(value);
        break;
      case "--version":
        values.version = value;
        break;
      default:
        fail(`unknown option ${name}`);
    }
  }
  if (
    values.archive === "" ||
    values.sbom === "" ||
    values.output === "" ||
    !/^[0-9a-f]{40}$/u.test(values.commit) ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(values.version)
  ) {
    fail("archive, Syft SBOM, output, version, and source commit are required");
  }
  return values;
}

function fail(message) {
  throw new Error(`artifact_sbom_finalize_failed:${message}`);
}
