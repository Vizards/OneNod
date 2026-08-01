import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { gzipSync } from "node:zlib";

const packageRoot = resolve(import.meta.dirname, "..");
const arguments_ = process.argv.slice(2);
let outputDirectory = resolve(packageRoot, "dist/worker");
if (arguments_.length === 2 && arguments_[0] === "--directory") {
  if (isAbsolute(arguments_[1])) {
    throw new Error("artifact audit failed: directory must be package-relative");
  }
  outputDirectory = resolve(packageRoot, arguments_[1]);
  const packageRelativePath = relative(packageRoot, outputDirectory);
  if (
    packageRelativePath === "" ||
    packageRelativePath === ".." ||
    packageRelativePath.startsWith(`..${sep}`)
  ) {
    throw new Error("artifact audit failed: directory escapes package root");
  }
} else if (arguments_.length !== 0) {
  throw new Error(
    "usage: audit-artifact.mjs [--directory PACKAGE_RELATIVE_PATH]",
  );
}
const expected = JSON.parse(
  await readFile(resolve(packageRoot, "evidence/expected-core.json"), "utf8"),
);
const files = await readdir(outputDirectory);
const wasmFiles = files.filter((name) => name.endsWith(".wasm"));
const scriptFiles = files.filter((name) => name.endsWith(".js"));

if (wasmFiles.length !== 1 || scriptFiles.length !== 1) {
  throw new Error("artifact audit failed: expected exactly one JS module and one WASM module");
}

const wasm = await readFile(resolve(outputDirectory, wasmFiles[0]));
const script = await readFile(resolve(outputDirectory, scriptFiles[0]), "utf8");
if (
  wasm.byteLength !== expected.processedBytes ||
  createHash("sha256").update(wasm).digest("hex") !== expected.processedSha256
) {
  throw new Error("artifact audit failed: uploaded WASM does not match verified core");
}
const wasmModule = new WebAssembly.Module(wasm);
if (WebAssembly.Module.customSections(wasmModule, expected.removedCustomSection).length !== 0) {
  throw new Error("artifact audit failed: removable custom section is still present");
}
if (
  WebAssembly.Module.exports(wasmModule).some(({ name }) =>
    name.startsWith(expected.removedExportPrefix),
  )
) {
  throw new Error("artifact audit failed: removable toolchain exports are still present");
}

const staticImports = [
  ...script.matchAll(/\bfrom["']([^"']+)["']/gu),
  ...script.matchAll(/\bimport["']([^"']+)["']/gu),
].map((match) => match[1]);
const allowedStaticImports = new Set([
  `./${wasmFiles[0]}`,
  "assert",
  "cloudflare:workers",
  "crypto",
  "node:buffer",
  "node:crypto",
]);
if (
  staticImports.length !== allowedStaticImports.size ||
  staticImports.some((specifier) => !allowedStaticImports.has(specifier)) ||
  [...allowedStaticImports].some((specifier) => !staticImports.includes(specifier))
) {
  throw new Error("artifact audit failed: static import capability set changed");
}

const forbidden = [
  ["Node __dirname", /__dirname/],
  ["Node __filename", /__filename/],
  ["dynamic import", /\bimport\s*\(/],
  ["dynamic require", /\brequire\s*\(/],
  ["native Node addon", /\.node\b/],
  ["Node process binding", /process\.(?:binding|dlopen|getBuiltinModule|mainModule)/],
  ["non-production 1Password host", /\.(?:b5local|b5staging|b5dev|b5test|b5rev)\.(?:com|ca|eu)/i],
  ["1Password Service Account token", /ops_[A-Za-z0-9_-]{20,}/],
  ["Cloudflare API token environment", /CLOUDFLARE_API_TOKEN/],
  ["public spike probe", /\/probe\//],
  ["test-only executor token", /SPIKE_RUN_TOKEN/],
];
for (const [label, pattern] of forbidden) {
  if (pattern.test(script)) {
    throw new Error(`artifact audit failed: found ${label}`);
  }
}

const deterministicGzipBytes =
  gzipSync(wasm, { level: 9 }).byteLength +
  gzipSync(Buffer.from(script), { level: 9 }).byteLength;
console.log(
  JSON.stringify({
    event: "artifact_audit_passed",
    deterministicGzipBytes,
    jsBytes: Buffer.byteLength(script),
    wasmBytes: wasm.byteLength,
    note: "Wrangler dry-run output is authoritative for upload compression",
  }),
);
