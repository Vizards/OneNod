import { lstat } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { parseProductVersion, parseStableVersion } from "./release-version.mjs";

const options = parseOptions(process.argv.slice(2));
await assertExecutable(options.may, "may");
await assertExecutable(options.helper, "Keychain helper");

const may = runJSON(options.may, ["version", "--json"], "may version");
if (
  may.version !== options.version ||
  may.release_tag !== options.tag ||
  may.source_commit !== options.commit ||
  may.repository !== "Vizards/OneNod" ||
  may.release_channel !== options.channel ||
  may.supported_release !== true ||
  may.client_protocol !== 1
) {
  fail("may reports release metadata that differs from the tagged build");
}

const helper = runJSON(
  options.helper,
  ["--version", "--json"],
  "Keychain helper version",
);
if (
  helper.ok !== true ||
  helper.version !== options.helperVersion ||
  typeof helper.source_commit !== "string" ||
  !/^[0-9a-f]{40}$/u.test(helper.source_commit) ||
  helper.protocol !== 1
) {
  fail("Keychain helper reports metadata that differs from the tagged build");
}

process.stdout.write(
  `${JSON.stringify({
    event: "release_binary_versions_verified",
    helper_version: helper.version,
    release_channel: may.release_channel,
    release_version: may.version,
  })}\n`,
);

function runJSON(command, args, label) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    fail(`${label} failed with status ${result.status ?? "signal"}`);
  }
  try {
    const parsed = JSON.parse(result.stdout);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      fail(`${label} did not return a JSON object`);
    }
    return parsed;
  } catch (error) {
    if (error instanceof SyntaxError) fail(`${label} did not return valid JSON`);
    throw error;
  }
}

async function assertExecutable(path, label) {
  const info = await lstat(path).catch(() => null);
  if (
    info === null ||
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.size <= 0 ||
    (info.mode & 0o111) === 0
  ) {
    fail(`${label} must be a nonempty regular executable`);
  }
}

function parseOptions(args) {
  const values = {
    channel: "",
    commit: "",
    helper: "",
    helperVersion: "",
    may: "",
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
      case "--helper":
        values.helper = resolve(value);
        break;
      case "--helper-version":
        values.helperVersion = value;
        break;
      case "--may":
        values.may = resolve(value);
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
    values.may === "" ||
    values.helper === "" ||
    !/^[0-9a-f]{40}$/u.test(values.commit) ||
    values.tag !== `v${values.version}`
  ) {
    fail("binary verification arguments are invalid");
  }
  const releaseVersion = parseProductVersion(values.version);
  if (releaseVersion === null || releaseVersion.channel !== values.channel) {
    fail("release version and channel are inconsistent");
  }
  if (parseStableVersion(values.helperVersion) === null) {
    fail("helper version must be a stable semantic version");
  }
  return values;
}

function fail(message) {
  throw new Error(`release_binary_verification_failed:${message}`);
}
