import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  removeCustomSection,
  removeExportsByPrefix,
} from "./wasm-custom-sections.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const expected = JSON.parse(
  await readFile(resolve(packageRoot, "evidence/expected-core.json"), "utf8"),
);
const licensePath = resolve(packageRoot, "evidence", expected.licenseFile);
const license = await readFile(licensePath);
if (
  expected.repository !== "https://github.com/1Password/onepassword-sdk-go" ||
  expected.license !== "MIT" ||
  expected.copyright !== "Copyright (c) 2024 1Password" ||
  sha256(license) !== expected.licenseSha256 ||
  !license.toString("utf8").includes(expected.copyright)
) {
  throw new Error("core integrity failure: pinned source attribution changed");
}
const vendorDirectory = resolve(packageRoot, "vendor");
const sourcePath = resolve(vendorDirectory, "core.original.wasm");
const temporarySourcePath = `${sourcePath}.download`;
const outputPath = resolve(packageRoot, "src/core.wasm");
const temporaryOutputPath = `${outputPath}.tmp`;

await mkdir(vendorDirectory, { recursive: true });
await mkdir(dirname(outputPath), { recursive: true });

let source;
try {
  source = await readFile(sourcePath);
  verifySource(source);
} catch (error) {
  if (error instanceof Error && error.message.startsWith("core integrity failure:")) {
    throw error;
  }
  source = await downloadSource();
}

const wasmOpt = resolve(packageRoot, "node_modules/.bin/wasm-opt");
const strip = spawnSync(wasmOpt, [sourcePath, "--strip-debug", "-o", temporaryOutputPath], {
  cwd: packageRoot,
  encoding: "utf8",
});
if (strip.status !== 0) {
  await rm(temporaryOutputPath, { force: true });
  throw new Error(`wasm-opt failed (${strip.status ?? "signal"}): ${strip.stderr.trim()}`);
}

const wasmOptOutput = await readFile(temporaryOutputPath);
const customSection = removeCustomSection(
  wasmOptOutput,
  expected.removedCustomSection,
);
if (customSection.removedCount !== 1) {
  await rm(temporaryOutputPath, { force: true });
  throw new Error("core integrity failure: expected exactly one removable custom section");
}
const prunedExports = removeExportsByPrefix(
  customSection.bytes,
  expected.removedExportPrefix,
);
if (prunedExports.removedCount !== expected.removedExportCount) {
  await rm(temporaryOutputPath, { force: true });
  throw new Error("core integrity failure: unexpected removable export count");
}
const processed = prunedExports.bytes;
await writeFile(temporaryOutputPath, processed);
verifyProcessed(processed);
verifyInterface(source, processed);
await rename(temporaryOutputPath, outputPath);

const generatedDirectory = resolve(packageRoot, "evidence/generated");
await mkdir(generatedDirectory, { recursive: true });
await writeFile(
  resolve(generatedDirectory, "core-build.json"),
  `${JSON.stringify(
    {
      sourceTag: expected.sourceTag,
      original: describe(source),
      processed: describe(processed),
      removedCustomSection: expected.removedCustomSection,
      removedExportPrefix: expected.removedExportPrefix,
      removedExportCount: prunedExports.removedCount,
      imports: moduleImports(processed),
      exports: moduleExports(processed),
    },
    null,
    2,
  )}\n`,
  "utf8",
);

console.log(
  JSON.stringify({
    event: "core_build_verified",
    originalBytes: source.byteLength,
    processedBytes: processed.byteLength,
    processedSha256: sha256(processed),
    removedCustomSection: expected.removedCustomSection,
    removedExportCount: prunedExports.removedCount,
  }),
);

async function downloadSource() {
  const response = await fetch(expected.source, { redirect: "error" });
  if (!response.ok) {
    throw new Error(`failed to download pinned core: HTTP ${response.status}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  verifySource(bytes);
  await writeFile(temporarySourcePath, bytes, { flag: "wx" }).catch(async (error) => {
    await rm(temporarySourcePath, { force: true });
    throw error;
  });
  await rename(temporarySourcePath, sourcePath);
  return bytes;
}

function verifySource(bytes) {
  const actual = describe(bytes);
  if (
    actual.bytes !== expected.originalBytes ||
    actual.sha256 !== expected.originalSha256 ||
    actual.gitBlobSha1 !== expected.originalGitBlobSha1
  ) {
    throw new Error("core integrity failure: pinned source hash or size changed");
  }
}

function verifyProcessed(bytes) {
  const actual = describe(bytes);
  if (actual.bytes !== expected.processedBytes || actual.sha256 !== expected.processedSha256) {
    throw new Error("core integrity failure: deterministic stripped output changed");
  }
}

function verifyInterface(original, processed) {
  const originalModule = new WebAssembly.Module(original);
  const processedModule = new WebAssembly.Module(processed);
  const originalImports = WebAssembly.Module.imports(originalModule);
  const processedImports = WebAssembly.Module.imports(processedModule);
  if (JSON.stringify(originalImports) !== JSON.stringify(processedImports)) {
    throw new Error("core integrity failure: transform changed WASM imports");
  }

  const expectedExports = WebAssembly.Module.exports(originalModule).filter(
    ({ name }) => !name.startsWith(expected.removedExportPrefix),
  );
  const processedExports = WebAssembly.Module.exports(processedModule);
  if (JSON.stringify(expectedExports) !== JSON.stringify(processedExports)) {
    throw new Error("core integrity failure: transform changed retained WASM exports");
  }
}

function describe(bytes) {
  return {
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
    gitBlobSha1: createHash("sha1")
      .update(`blob ${bytes.byteLength}\0`)
      .update(bytes)
      .digest("hex"),
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function moduleImports(bytes) {
  return WebAssembly.Module.imports(new WebAssembly.Module(bytes));
}

function moduleExports(bytes) {
  return WebAssembly.Module.exports(new WebAssembly.Module(bytes));
}
