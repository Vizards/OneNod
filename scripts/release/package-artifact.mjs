import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

import { writeArtifactArchive } from "./artifact-tar.mjs";
import { parseProductVersion, parseStableVersion } from "./release-version.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const releaseContract = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "scripts/release/release-contract.json"),
    "utf8",
  ),
);
const options = parseOptions(process.argv.slice(2));
const temporaryDirectory = await mkdtemp(join(tmpdir(), "onenod-release-"));

try {
  let archiveRoot;
  switch (options.kind) {
    case "local":
      archiveRoot = await stageLocalArtifact(temporaryDirectory, options);
      break;
    case "helper":
      archiveRoot = await stageHelperArtifact(temporaryDirectory, options);
      break;
    case "deployment":
      archiveRoot = await stageDeploymentArtifact(temporaryDirectory, options);
      break;
    case "skill":
      archiveRoot = await stageSkillArtifact(temporaryDirectory, options);
      break;
    default:
      fail(`unsupported artifact kind ${options.kind}`);
  }
  await createDeterministicTarGzip(
    temporaryDirectory,
    basename(archiveRoot),
    options.output,
  );
  process.stdout.write(
    `${JSON.stringify({ artifact: options.output, kind: options.kind })}\n`,
  );
} finally {
  await rm(temporaryDirectory, { force: true, recursive: true });
}

async function stageLocalArtifact(temporaryRoot, values) {
  const root = join(temporaryRoot, "onenod");
  const binaryDirectory = join(root, "bin");
  await mkdir(binaryDirectory, { recursive: true, mode: 0o755 });
  const mayPath = join(binaryDirectory, "may");
  const adapterPath = join(binaryDirectory, "may-ssh-sign");
  await copyExecutable(values.binary, mayPath);
  await copyExecutable(values.adapterBinary, adapterPath);
  await copyRequiredFile(resolve(repositoryRoot, "LICENSE"), join(root, "LICENSE"));
  await stageThirdPartyInventory(root, values);
  await writeReleaseMetadata(root, {
    architecture: values.arch,
    artifact_kind: "local",
    code_identities: {
      may: releaseContract.components?.may?.code_identity,
      may_ssh_sign:
        releaseContract.components?.may?.adapter_code_identity,
    },
    binary_sha256: {
      may: await sha256File(mayPath),
      may_ssh_sign: await sha256File(adapterPath),
    },
    exact_code_identities: {
      may: await exactCodeIdentity(mayPath, values.arch),
      may_ssh_sign: await exactCodeIdentity(adapterPath, values.arch),
    },
    release_version: values.version,
    source_commit: values.commit,
  });
  return root;
}

async function stageHelperArtifact(temporaryRoot, values) {
  const helperProtocol =
    releaseContract.components?.keychain_helper?.helper_protocol;
  if (
    !Number.isSafeInteger(helperProtocol?.min) ||
    helperProtocol.min !== helperProtocol.max
  ) {
    fail("release contract must select one Keychain helper protocol");
  }
  const root = join(temporaryRoot, "onenod-keychain-helper");
  const binaryDirectory = join(root, "bin");
  await mkdir(binaryDirectory, { recursive: true, mode: 0o755 });
  const helperPath = join(binaryDirectory, "onenod-keychain-helper");
  await copyExecutable(
    values.binary,
    helperPath,
  );
  await copyRequiredFile(resolve(repositoryRoot, "LICENSE"), join(root, "LICENSE"));
  await stageThirdPartyInventory(root, values);
  await writeReleaseMetadata(root, {
    architecture: values.arch,
    artifact_kind: "keychain_helper",
    binary_sha256: await sha256File(helperPath),
    code_identity: releaseContract.components?.keychain_helper?.code_identity,
    exact_code_identity: await exactCodeIdentity(helperPath, values.arch),
    helper_protocol: helperProtocol.min,
    helper_source_digest: values.helperSourceDigest,
    helper_version: values.helperVersion,
    source_commit: values.commit,
  });
  return root;
}

async function stageDeploymentArtifact(temporaryRoot, values) {
  const root = join(temporaryRoot, "onenod-deployment");
  await copyTree(
    resolve(repositoryRoot, "apps/gateway/dist/web"),
    join(root, "gateway/assets"),
  );
  await copyRequiredFile(
    resolve(repositoryRoot, "apps/gateway/dist/worker/index.js"),
    join(root, "gateway/worker.mjs"),
  );
  await stageExecutorWorker(
    resolve(repositoryRoot, "apps/executor/dist/worker"),
    join(root, "executor"),
  );
  await copyRequiredFile(
    resolve(import.meta.dirname, "templates/gateway.wrangler.jsonc"),
    join(root, "gateway/wrangler.jsonc"),
  );
  await copyRequiredFile(
    resolve(import.meta.dirname, "templates/executor.wrangler.jsonc"),
    join(root, "executor/wrangler.jsonc"),
  );
  await copyRequiredFile(resolve(repositoryRoot, "LICENSE"), join(root, "LICENSE"));
  await stageThirdPartyInventory(root, values);
  await copyRequiredFile(
    resolve(
      repositoryRoot,
      "apps/executor/third_party/licenses/onepassword-sdk-go-0.4.1.txt",
    ),
    join(root, "executor/third-party/onepassword-sdk-go/LICENSE"),
  );
  await copyRequiredFile(
    resolve(repositoryRoot, "apps/executor/evidence/expected-core.json"),
    join(root, "executor/third-party/onepassword-sdk-go/SOURCE.json"),
  );
  await writeJSON(join(root, "deployment.json"), {
    executor: {
      config: "executor/wrangler.jsonc",
      entrypoint: "executor/worker.mjs",
      plugin: "executor/plugin.wasm",
    },
    gateway: {
      assets: "gateway/assets",
      config: "gateway/wrangler.jsonc",
      entrypoint: "gateway/worker.mjs",
    },
    release_version: values.version,
    schema_version: 1,
    source_commit: values.commit,
    template_tokens: [
      "__ACCOUNT_ID__",
      "__ACCOUNT_SUBDOMAIN__",
      "__GATEWAY_NAME__",
      "__EXECUTOR_NAME__",
      "__ORIGIN__",
      "__RP_ID__",
      "__OP_ACCOUNT__",
      "__OP_VAULT_ID__",
      "__VAPID_PUBLIC_KEY__",
      "__RELEASE_VERSION__",
      "__SOURCE_COMMIT__",
    ],
  });
  await writeJSON(join(root, "RELEASE.json"), {
    artifact_kind: "deployment",
    release_version: values.version,
    repository: "Vizards/OneNod",
    schema_version: 1,
    source_commit: values.commit,
  });
  return root;
}

async function stageSkillArtifact(temporaryRoot, values) {
  const root = join(temporaryRoot, "onenod-skill");
  await copyTree(resolve(repositoryRoot, "skills/onenod"), join(root, "onenod"));
  await copyRequiredFile(resolve(repositoryRoot, "LICENSE"), join(root, "LICENSE"));
  await writeReleaseMetadata(root, {
    artifact_kind: "skill",
    release_version: values.version,
    source_commit: values.commit,
  });
  return root;
}

async function stageThirdPartyInventory(root, values) {
  await copyRequiredFile(
    values.notices,
    join(root, "THIRD_PARTY_NOTICES.txt"),
  );
  await copyRequiredFile(
    values.components,
    join(root, "THIRD_PARTY_COMPONENTS.json"),
  );
}

async function writeReleaseMetadata(root, metadata) {
  await writeJSON(join(root, "RELEASE.json"), {
    repository: "Vizards/OneNod",
    schema_version: 1,
    ...metadata,
  });
}

async function copyExecutable(source, destination) {
  await assertRegularFile(source, "release binary");
  await copyRequiredFile(source, destination);
  await chmod(destination, 0o755);
}

async function copyRequiredFile(source, destination) {
  await assertRegularFile(source, `required file ${source}`);
  await mkdir(dirname(destination), { recursive: true, mode: 0o755 });
  await copyFile(source, destination);
  const sourceInfo = await lstat(source);
  await chmod(destination, sourceInfo.mode & 0o111 ? 0o755 : 0o644);
}

async function copyTree(source, destination) {
  const info = await lstat(source).catch(() => null);
  if (info === null || !info.isDirectory() || info.isSymbolicLink()) {
    fail(`required release directory is unavailable: ${source}`);
  }
  await mkdir(destination, { recursive: true, mode: 0o755 });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    if (entry.name === ".DS_Store") continue;
    const sourcePath = join(source, entry.name);
    const destinationPath = join(destination, entry.name);
    if (entry.isSymbolicLink()) {
      fail(`release inputs may not contain symbolic links: ${sourcePath}`);
    }
    if (entry.isDirectory()) {
      await copyTree(sourcePath, destinationPath);
    } else if (entry.isFile()) {
      await copyRequiredFile(sourcePath, destinationPath);
    } else {
      fail(`unsupported release input: ${sourcePath}`);
    }
  }
}

async function stageExecutorWorker(source, destination) {
  const entries = await readdir(source, { withFileTypes: true }).catch(() => null);
  if (entries === null) fail(`required release directory is unavailable: ${source}`);
  const wasmFiles = entries.filter(
    (entry) => entry.isFile() && entry.name.endsWith(".wasm"),
  );
  if (wasmFiles.length !== 1) {
    fail("Executor release build must contain exactly one WASM plugin");
  }
  const workerPath = join(source, "index.js");
  await assertRegularFile(workerPath, "Executor Worker bundle");
  const worker = await readFile(workerPath, "utf8");
  const originalImport = `./${wasmFiles[0].name}`;
  const importCount = worker.split(originalImport).length - 1;
  if (importCount !== 1) {
    fail("Executor Worker bundle must import its hashed WASM plugin exactly once");
  }
  await mkdir(destination, { recursive: true, mode: 0o755 });
  await writeFile(
    join(destination, "worker.mjs"),
    worker.replace(originalImport, "./plugin.wasm"),
    { encoding: "utf8", flag: "wx", mode: 0o644 },
  );
  await copyRequiredFile(
    join(source, wasmFiles[0].name),
    join(destination, "plugin.wasm"),
  );
}

async function writeJSON(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
}

async function createDeterministicTarGzip(baseDirectory, archiveRootName, output) {
  const sourceRoot = join(baseDirectory, archiveRootName);
  const files = await collectFiles(sourceRoot);
  const entries = [];
  for (const file of files) {
    const archivePath = `${archiveRootName}/${file.path}`;
    const content = await readFile(file.absolutePath);
    entries.push({ content, mode: file.mode, name: archivePath });
  }
  await writeArtifactArchive(output, entries);
}

async function collectFiles(root) {
  const collected = [];
  await walk(root);
  collected.sort((left, right) => left.path.localeCompare(right.path, "en"));
  return collected;

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolutePath = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        fail(`release staging may not contain symbolic links: ${absolutePath}`);
      }
      if (entry.isDirectory()) {
        await walk(absolutePath);
      } else if (entry.isFile()) {
        const info = await lstat(absolutePath);
        collected.push({
          absolutePath,
          mode: info.mode & 0o111 ? 0o755 : 0o644,
          path: relative(root, absolutePath).split(sep).join("/"),
        });
      } else {
        fail(`unsupported staged release input: ${absolutePath}`);
      }
    }
  }
}

async function assertRegularFile(path, label) {
  const info = await lstat(path).catch(() => null);
  if (info === null || !info.isFile() || info.isSymbolicLink()) {
    fail(`${label} must be a regular file: ${path}`);
  }
  if (info.size <= 0) fail(`${label} is empty: ${path}`);
}

async function sha256File(path) {
  return `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

async function exactCodeIdentity(path, architecture) {
  const expectedMachOArchitecture = architecture === "amd64" ? "x86_64" : architecture;
  const architectures = spawnSync("/usr/bin/lipo", ["-archs", path], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const slices = (architectures.stdout ?? "").trim().split(/\s+/u).filter(Boolean);
  if (
    architectures.status !== 0 ||
    slices.length !== 1 ||
    slices[0] !== expectedMachOArchitecture
  ) {
    fail(`release binary does not contain exactly the declared architecture: ${path}`);
  }
  const details = spawnSync(
    "/usr/bin/codesign",
    ["-d", "--verbose=4", "-r-", path],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const output = `${details.stdout ?? ""}\n${details.stderr ?? ""}`;
  if (details.status !== 0) fail(`cannot inspect exact code identity: ${path}`);
  const cdhashHex = /^CDHash=([0-9a-f]+)$/imu.exec(output)?.[1]?.toLowerCase();
  const requirement = /^(?:# )?designated => (.+)$/mu.exec(output)?.[1];
  if (
    cdhashHex === undefined ||
    cdhashHex.length < 40 ||
    cdhashHex.length > 128 ||
    cdhashHex.length % 2 !== 0 ||
    requirement === undefined ||
    requirement.length === 0
  ) {
    fail(`exact code identity is incomplete: ${path}`);
  }
  const requirementPath = join(
    temporaryDirectory,
    `.requirement-${createHash("sha256").update(path).digest("hex")}`,
  );
  const compiled = spawnSync(
    "/usr/bin/csreq",
    [`-r=${requirement}`, "-b", requirementPath],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (compiled.status !== 0) fail(`cannot compile exact designated requirement: ${path}`);
  const requirementData = await readFile(requirementPath);
  await rm(requirementPath, { force: true });
  if (requirementData.length === 0 || requirementData.length > 64 * 1024) {
    fail(`compiled designated requirement is invalid: ${path}`);
  }
  return {
    architecture,
    cdhash: Buffer.from(cdhashHex, "hex").toString("base64url"),
    designated_requirement_data_sha256: `sha256:${createHash("sha256")
      .update(requirementData)
      .digest("hex")}`,
  };
}

function parseOptions(args) {
  const values = {
    arch: "",
    adapterBinary: "",
    binary: "",
    commit: "",
    components: "",
    helperSourceDigest: "",
    helperVersion: "",
    kind: "",
    notices: "",
    output: "",
    version: "",
  };
  if (args.length === 0) fail("artifact kind is required");
  values.kind = args[0];
  for (let index = 1; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (value === undefined) fail(`missing value for ${name}`);
    switch (name) {
      case "--arch":
        values.arch = value;
        break;
      case "--adapter-binary":
        values.adapterBinary = resolve(value);
        break;
      case "--binary":
        values.binary = resolve(value);
        break;
      case "--commit":
        values.commit = value;
        break;
      case "--components":
        values.components = resolve(value);
        break;
      case "--helper-version":
        values.helperVersion = value;
        break;
      case "--notices":
        values.notices = resolve(value);
        break;
      case "--helper-source-digest":
        values.helperSourceDigest = value;
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
  if (values.output === "" || !/^[0-9a-f]{40}$/u.test(values.commit)) {
    fail("output and a full lowercase source commit are required");
  }
  if (["local", "deployment", "skill"].includes(values.kind)) {
    requireProductVersion(values.version, "release version");
  }
  if (["local", "helper", "deployment"].includes(values.kind)) {
    if (values.notices === "" || values.components === "") {
      fail(`${values.kind} artifacts require third-party notices and component inventory`);
    }
  }
  if (["local", "helper"].includes(values.kind)) {
    if (!["arm64", "amd64"].includes(values.arch) || values.binary === "") {
      fail("local and helper artifacts require a binary and supported architecture");
    }
  }
  if (values.kind === "local" && values.adapterBinary === "") {
    fail("local artifacts require the exact may SSH signing adapter binary");
  }
  if (values.kind === "helper") {
    requireStableVersion(values.helperVersion, "helper version");
    if (!/^sha256:[0-9a-f]{64}$/u.test(values.helperSourceDigest)) {
      fail("helper artifact requires its production source digest");
    }
  }
  return values;
}

function requireProductVersion(value, label) {
  if (parseProductVersion(value) === null) {
    fail(`${label} must be stable SemVer or use the exact alpha.N/beta.N form`);
  }
}

function requireStableVersion(value, label) {
  if (parseStableVersion(value) === null) {
    fail(`${label} must be a stable semantic version`);
  }
}

function fail(message) {
  throw new Error(`release_packaging_failed:${message}`);
}
