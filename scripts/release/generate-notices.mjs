import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

import { parseProductVersion } from "./release-version.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const options = parseOptions(process.argv.slice(2));
const sections = [];
const components = [];

if (options.scope === "deployment") {
  await collectNodeDependencies();
  await collectVendoredWorkerDependencies();
}
if (options.scope === "binary") {
  await collectGoBinaryDependencies(options.binary);
}

components.sort(compareComponents);
for (let index = 1; index < components.length; index += 1) {
  if (componentKey(components[index - 1]) === componentKey(components[index])) {
    fail(`duplicate third-party component ${componentKey(components[index])}`);
  }
}

const lines = [
  "OneNod Third-Party Notices",
  "==========================",
  "",
  "Format: 2",
  `Release: ${options.version}`,
  `Source commit: ${options.commit}`,
  `Scope: ${options.scope}`,
  `Components: ${components.length}`,
  `Component inventory SHA-256: ${sha256(Buffer.from(JSON.stringify(components)))}`,
  "",
  "This file carries the copyright, license, and NOTICE material discovered",
  "from the exact production dependency set for this artifact scope.",
  "OneNod's own terms are in the adjacent LICENSE file.",
  "",
];
const documentCatalog = new Map();
for (const section of sections) {
  for (const document of section.documents) {
    const digest = sha256(Buffer.from(document.content));
    if (!documentCatalog.has(digest)) documentCatalog.set(digest, document);
  }
}
for (const section of sections.sort((left, right) =>
  left.heading.localeCompare(right.heading, "en"),
)) {
  lines.push(section.heading, "-".repeat(section.heading.length));
  for (const metadata of section.metadata) lines.push(metadata);
  for (const document of section.documents) {
    lines.push(
      `Material: ${document.kind} sha256:${sha256(Buffer.from(document.content))} (${document.name})`,
    );
  }
  lines.push("");
}
lines.push("Full third-party license and NOTICE texts", "========================================", "");
for (const [digest, document] of [...documentCatalog.entries()].sort()) {
  lines.push(`--- BEGIN ${document.kind} sha256:${digest} (${document.name}) ---`);
  lines.push(document.content.trimEnd());
  lines.push(`--- END ${document.kind} sha256:${digest} (${document.name}) ---`, "");
}

const notices = `${lines.join("\n").trimEnd()}\n`;
if (/\b(?:UNLICENSED|UNKNOWN|NOASSERTION)\b|SEE LICENSE IN/iu.test(notices)) {
  fail("notice output contains an unresolved license state");
}
await writeFile(options.output, notices, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});

if (options.inventoryOutput !== "") {
  await writeFile(
    options.inventoryOutput,
    `${JSON.stringify(
      {
        schema_version: 1,
        scope: options.scope,
        release_version: options.version,
        source_commit: options.commit,
        components,
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o644 },
  );
}

process.stdout.write(
  `${JSON.stringify({
    components: components.length,
    inventory: options.inventoryOutput || null,
    output: options.output,
    scope: options.scope,
  })}\n`,
);

async function collectNodeDependencies() {
  const inventory = runJSON(
    "pnpm",
    ["licenses", "list", "--prod", "--long", "--json"],
    repositoryRoot,
    "pnpm license inventory",
  );
  for (const [declaredLicense, entries] of Object.entries(inventory)) {
    reviewedLicense(declaredLicense, "Node package license");
    if (!Array.isArray(entries)) fail("pnpm license inventory has an invalid shape");
    for (const entry of entries) {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
        fail("pnpm license inventory contains an invalid package");
      }
      const inventoryName = safeLine(entry.name, "Node package name");
      const paths = Array.isArray(entry.paths) ? entry.paths : [];
      if (paths.length === 0) fail(`Node package ${inventoryName} has no installed path`);
      const documents = await collectDocuments(paths);
      if (!documents.some(({ kind }) => kind === "LICENSE")) {
        fail(`Node package ${inventoryName} carries no complete license text`);
      }
      const packageVersions = new Set();
      for (const path of paths) {
        const manifest = parseRecord(
          await readFile(resolve(path, "package.json"), "utf8"),
          `${inventoryName} package manifest`,
        );
        const name = safeLine(manifest.name, "installed Node package name");
        const version = safeLine(manifest.version, "installed Node package version");
        const manifestLicense =
          typeof manifest.license === "string"
            ? manifest.license
            : legacyManifestLicense(manifest.licenses);
        const license = reviewedLicense(
          manifestLicense,
          `installed Node package ${name}@${version} license`,
        );
        if (name !== inventoryName || license !== declaredLicense) {
          fail(`pnpm license metadata differs from ${name}@${version}`);
        }
        packageVersions.add(version);
        components.push({
          ecosystem: "npm",
          license,
          name,
          purl: npmPurl(name, version),
          source:
            typeof entry.homepage === "string" && safeOptionalLine(entry.homepage)
              ? entry.homepage
              : `https://www.npmjs.com/package/${name}/v/${version}`,
          version,
        });
      }
      const versions = [...packageVersions].sort(compareVersions);
      const reportedVersions = Array.isArray(entry.versions)
        ? [...new Set(entry.versions)].sort(compareVersions)
        : [];
      if (JSON.stringify(versions) !== JSON.stringify(reportedVersions)) {
        fail(`pnpm version inventory differs from installed ${inventoryName}`);
      }
      sections.push({
        documents,
        heading: `npm: ${inventoryName}@${versions.join(",")}`,
        metadata: [
          `License: ${declaredLicense}`,
          ...(typeof entry.homepage === "string" && safeOptionalLine(entry.homepage)
            ? [`Source: ${entry.homepage}`]
            : []),
        ],
      });
    }
  }
}

async function collectVendoredWorkerDependencies() {
  const evidencePath = resolve(
    repositoryRoot,
    "apps/executor/evidence/expected-core.json",
  );
  const evidence = parseRecord(
    await readFile(evidencePath, "utf8"),
    "1Password core source evidence",
  );
  const licensePath = resolve(
    repositoryRoot,
    "apps/executor/evidence",
    safeLine(evidence.licenseFile, "1Password license path"),
  );
  const license = await requiredText(licensePath);
  if (
    evidence.repository !== "https://github.com/1Password/onepassword-sdk-go" ||
    evidence.sourceTag !== "v0.4.1" ||
    evidence.license !== "MIT" ||
    evidence.copyright !== "Copyright (c) 2024 1Password" ||
    sha256(Buffer.from(license)) !== evidence.licenseSha256 ||
    classifyLicense(license) !== "MIT" ||
    !license.includes(evidence.copyright) ||
    !/^[0-9a-f]{64}$/u.test(evidence.originalSha256) ||
    !/^[0-9a-f]{64}$/u.test(evidence.processedSha256)
  ) {
    fail("pinned 1Password core attribution or digest evidence changed");
  }
  components.push({
    ecosystem: "wasm",
    license: "MIT",
    name: "github.com/1Password/onepassword-sdk-go/internal/wasm/core.wasm",
    original_sha256: `sha256:${evidence.originalSha256}`,
    processed_sha256: `sha256:${evidence.processedSha256}`,
    source: safeLine(evidence.source, "1Password core source URL"),
    version: evidence.sourceTag,
  });
  sections.push({
    documents: [licenseDocument(licensePath, license)],
    heading: `wasm: 1Password onepassword-sdk-go core.wasm@${evidence.sourceTag}`,
    metadata: [
      "License: MIT",
      `Copyright: ${evidence.copyright}`,
      `Repository: ${evidence.repository}`,
      `Source: ${evidence.source}`,
      `Original SHA-256: ${evidence.originalSha256}`,
      `Processed SHA-256: ${evidence.processedSha256}`,
      `Transform: ${safeLine(evidence.stripTool, "1Password core transform")}`,
    ],
  });
}

async function collectGoBinaryDependencies(binary) {
  const metadata = run("go", ["version", "-m", binary], repositoryRoot, "Go binary inventory");
  await collectGoToolchain(metadata);
  const dependencies = [];
  for (const line of metadata.split("\n")) {
    const fields = line.split("\t");
    if (fields[0] !== "" || fields[1] !== "dep") continue;
    if (fields.length < 4 || fields[2] === "" || fields[3] === "") {
      fail("Go binary contains an incomplete dependency record");
    }
    dependencies.push({ name: fields[2], version: fields[3] });
  }
  dependencies.sort(compareComponents);
  for (const dependency of dependencies) {
    const download = runJSON(
      "go",
      ["mod", "download", "-json", `${dependency.name}@${dependency.version}`],
      resolve(repositoryRoot, "cmd/may"),
      `Go module download ${dependency.name}@${dependency.version}`,
    );
    if (typeof download.Error === "string" || typeof download.Dir !== "string") {
      fail(`Go module ${dependency.name}@${dependency.version} is unavailable`);
    }
    const documents = await collectDocuments([download.Dir]);
    const licenseDocuments = documents.filter(({ kind }) => kind === "LICENSE");
    if (licenseDocuments.length === 0) {
      fail(`Go module ${dependency.name}@${dependency.version} has no license text`);
    }
    const detected = [...new Set(licenseDocuments.map(({ content }) =>
      classifyLicense(content),
    ))];
    if (detected.includes("") || detected.length !== 1) {
      fail(`Go module ${dependency.name}@${dependency.version} has an unreviewed license`);
    }
    const license = reviewedLicense(
      detected[0],
      `Go module ${dependency.name}@${dependency.version} license`,
    );
    const source = `https://pkg.go.dev/${dependency.name}@${dependency.version}`;
    components.push({
      ecosystem: "go",
      license,
      name: dependency.name,
      purl: goPurl(dependency.name, dependency.version),
      source,
      version: dependency.version,
    });
    sections.push({
      documents,
      heading: `go: ${dependency.name}@${dependency.version}`,
      metadata: [`License: ${license}`, `Source: ${source}`],
    });
  }
}

async function collectGoToolchain(binaryMetadata) {
  const runtimeMatch = /^[^\n:]+:\s+(go\d+\.\d+(?:\.\d+)?)$/mu.exec(binaryMetadata);
  if (runtimeMatch === null) fail("Go binary does not declare a stable toolchain version");
  const version = runtimeMatch[1];
  const goRoot = run("go", ["env", "GOROOT"], repositoryRoot, "Go toolchain root").trim();
  const toolVersion = run("go", ["version"], repositoryRoot, "Go toolchain version");
  const versionFile = await requiredText(resolve(goRoot, "VERSION"));
  if (
    !toolVersion.includes(` ${version} `) ||
    versionFile.split("\n", 1)[0] !== version
  ) {
    fail(`built binary toolchain ${version} differs from the active GOROOT`);
  }
  let licensePath = resolve(goRoot, "LICENSE");
  const licenseInfo = await lstat(licensePath).catch(() => null);
  if (licenseInfo === null) licensePath = resolve(dirname(goRoot), "LICENSE");
  const patentsPath = resolve(goRoot, "PATENTS");
  const license = await requiredText(licensePath);
  const patents = await requiredText(patentsPath);
  if (classifyLicense(license) !== "BSD-3-Clause") {
    fail(`Go toolchain ${version} license changed`);
  }
  components.push({
    ecosystem: "go-toolchain",
    license: "BSD-3-Clause",
    name: "Go standard library and runtime",
    purl: `pkg:generic/golang@${encodeURIComponent(version.slice(2))}`,
    source: `https://go.dev/dl/#${version}`,
    version,
  });
  sections.push({
    documents: [
      licenseDocument(licensePath, license),
      { content: patents, kind: "PATENTS", name: basename(patentsPath) },
    ],
    heading: `go-toolchain: Go standard library and runtime@${version}`,
    metadata: [
      "License: BSD-3-Clause",
      `Source: https://go.dev/dl/#${version}`,
      `Toolchain VERSION: ${versionFile.trimEnd().replaceAll("\n", "; ")}`,
    ],
  });
}

async function collectDocuments(directories) {
  const byDigest = new Map();
  for (const directory of directories) {
    const info = await lstat(directory).catch(() => null);
    if (info === null || !info.isDirectory() || info.isSymbolicLink()) {
      fail("dependency license directory is not a regular directory");
    }
    const names = (await readdir(directory)).sort((left, right) =>
      left.localeCompare(right, "en"),
    );
    for (const name of names) {
      const kind = documentKind(name);
      if (kind === "") continue;
      const path = resolve(directory, name);
      const content = await requiredText(path);
      const digest = sha256(Buffer.from(content));
      if (!byDigest.has(digest)) {
        byDigest.set(digest, { content, kind, name: basename(path) });
      }
    }
  }
  return [...byDigest.values()].sort((left, right) => {
    const byKind = left.kind.localeCompare(right.kind, "en");
    return byKind === 0 ? left.name.localeCompare(right.name, "en") : byKind;
  });
}

function documentKind(name) {
  if (/^licen[cs]e(?:\.(?:md|txt))?$/iu.test(name)) return "LICENSE";
  if (/^licen[cs]e-(?:mit|cc0)$/iu.test(name)) return "LICENSE";
  if (/^copying(?:\.(?:md|txt))?$/iu.test(name)) return "LICENSE";
  if (/^notice(?:\.(?:md|txt))?$/iu.test(name)) return "NOTICE";
  return "";
}

function licenseDocument(path, content) {
  return { content, kind: "LICENSE", name: basename(path) };
}

function classifyLicense(value) {
  const text = value.replaceAll("\r\n", "\n");
  if (/two different licenses:\s*MIT and Apache/iu.test(text)) {
    return "(MIT AND Apache-2.0)";
  }
  if (/Apache License[\s\S]{0,80}Version 2\.0/iu.test(text) ||
      /Licensed under the Apache License, Version 2\.0/iu.test(text)) {
    return "Apache-2.0";
  }
  if (/Permission is hereby granted, free of charge/iu.test(text)) return "MIT";
  if (/BSD 2-Clause License/iu.test(text)) return "BSD-2-Clause";
  if (/Redistribution and use in source and binary forms/iu.test(text)) {
    return /Neither the name|names of its contributors/iu.test(text)
      ? "BSD-3-Clause"
      : "BSD-2-Clause";
  }
  if (/This is free and unencumbered software released into the public domain/iu.test(text)) {
    return "Unlicense";
  }
  if (/Copyright \(C\) 2000-2002 JSON\.org/iu.test(text)) return "JSON";
  return "";
}

function reviewedLicense(value, label) {
  const license = safeLine(value, label);
  const reviewed = new Set([
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "MIT",
    "Unlicense",
    "(MIT AND Apache-2.0)",
    "(MIT OR CC0-1.0)",
  ]);
  if (!reviewed.has(license)) fail(`${label} is not in the reviewed SPDX allowlist: ${license}`);
  return license;
}

function legacyManifestLicense(value) {
  if (!Array.isArray(value)) return "";
  const licenses = [
    ...new Set(
      value
        .map((entry) =>
          entry !== null && typeof entry === "object" && !Array.isArray(entry)
            ? entry.type
            : "",
        )
        .filter((entry) => typeof entry === "string" && entry !== ""),
    ),
  ];
  return licenses.length === 1 ? licenses[0] : "";
}

async function requiredText(path) {
  const info = await lstat(path).catch(() => null);
  if (info === null || !info.isFile() || info.isSymbolicLink() || info.size <= 0) {
    fail(`required license material is missing: ${path}`);
  }
  const value = (await readFile(path, "utf8")).replaceAll("\r\n", "\n");
  if (value.includes("\u0000")) fail(`license material is not text: ${path}`);
  return value;
}

function runJSON(command, args, cwd, label) {
  const output = run(command, args, cwd, label);
  return parseRecord(output, label);
}

function run(command, args, cwd, label) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    fail(`${label} failed with status ${result.status ?? "signal"}: ${result.stderr.trim()}`);
  }
  return result.stdout;
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

function componentKey(value) {
  return `${value.ecosystem}\u0000${value.name}\u0000${value.version}`;
}

function compareComponents(left, right) {
  return componentKey(left).localeCompare(componentKey(right), "en");
}

function npmPurl(name, version) {
  return `pkg:npm/${name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(version)}`;
}

function goPurl(name, version) {
  return `pkg:golang/${name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(version)}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function safeLine(value, label) {
  if (typeof value !== "string" || value === "" || !safeOptionalLine(value)) {
    fail(`${label} is invalid`);
  }
  return value;
}

function safeOptionalLine(value) {
  return (
    typeof value === "string" &&
    !value.includes("\u0000") &&
    !value.includes("\r") &&
    !value.includes("\n") &&
    !value.includes("\t") &&
    value.length <= 1024
  );
}

function compareVersions(left, right) {
  return left.localeCompare(right, "en", { numeric: true });
}

function parseOptions(args) {
  const values = {
    binary: "",
    commit: "",
    inventoryOutput: "",
    output: "",
    scope: "",
    version: "",
  };
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--binary":
        values.binary = resolve(value);
        break;
      case "--commit":
        values.commit = value;
        break;
      case "--inventory-output":
        values.inventoryOutput = resolve(value);
        break;
      case "--output":
        values.output = resolve(value);
        break;
      case "--scope":
        values.scope = value;
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
  if (!new Set(["binary", "deployment"]).has(values.scope)) {
    fail("notice scope must be binary or deployment");
  }
  if (values.scope === "binary" && values.binary === "") {
    fail(`${values.scope} notices require the built Go binary`);
  }
  if (values.output === "") fail("notices output path is required");
  return values;
}

function fail(message) {
  throw new Error(`release_notices_failed:${message}`);
}
