import semver from "semver";

const PRODUCT_PRERELEASE_CHANNELS = new Set(["alpha", "beta"]);

export function parseProductVersion(value) {
  if (typeof value !== "string") return null;
  const parsed = semver.parse(value, { includePrerelease: true, loose: false });
  if (parsed === null || parsed.version !== value || parsed.build.length !== 0) {
    return null;
  }
  if (parsed.prerelease.length === 0) {
    return { channel: "stable", version: parsed.version };
  }
  if (
    parsed.prerelease.length !== 2 ||
    typeof parsed.prerelease[0] !== "string" ||
    !PRODUCT_PRERELEASE_CHANNELS.has(parsed.prerelease[0]) ||
    typeof parsed.prerelease[1] !== "number" ||
    !Number.isSafeInteger(parsed.prerelease[1]) ||
    parsed.prerelease[1] < 1
  ) {
    return null;
  }
  return { channel: parsed.prerelease[0], version: parsed.version };
}

export function parseStableVersion(value) {
  const parsed = parseProductVersion(value);
  return parsed?.channel === "stable" ? parsed : null;
}

export function productVersionCore(value) {
  const parsed = parseProductVersion(value);
  return parsed === null ? null : parsed.version.split("-", 1)[0];
}

export function releaseTrainTarget(contract) {
  const parsed = parseStableVersion(contract.release_train?.target_version);
  return parsed?.version ?? null;
}

export function releaseMatchesTrain(contract, version) {
  const target = releaseTrainTarget(contract);
  const core = productVersionCore(version);
  return target !== null && core === target;
}

export function compareProductVersions(left, right) {
  const first = parseProductVersion(left);
  const second = parseProductVersion(right);
  if (first === null || second === null) {
    throw new TypeError("cannot compare invalid OneNod product versions");
  }
  return semver.compare(first.version, second.version);
}

export function releaseUpgradeVersionPolicy(upgrade, releaseVersion) {
  const minimumSafe = parseStableVersion(upgrade?.minimum_safe_version);
  if (minimumSafe === null) {
    return "minimum safe version must be a stable product version";
  }
  const minimumUpdater = parseProductVersion(upgrade?.minimum_updater_version);
  if (minimumUpdater === null) {
    return "minimum updater version must be a product version";
  }
  const release = parseProductVersion(releaseVersion);
  if (release === null) {
    return "release version must be a product version";
  }
  if (compareProductVersions(minimumSafe.version, release.version) > 0) {
    return "minimum safe version cannot exceed the published release";
  }
  if (compareProductVersions(minimumUpdater.version, release.version) > 0) {
    return "minimum updater version cannot exceed the published release";
  }
  return null;
}

export function releaseChannelPolicy(contract, version) {
  const parsed = parseProductVersion(version);
  if (parsed === null) return null;
  const policy = contract.release_channels?.[parsed.channel];
  if (
    policy === null ||
    typeof policy !== "object" ||
    Array.isArray(policy) ||
    typeof policy.github_prerelease !== "boolean" ||
    typeof policy.github_latest !== "boolean" ||
    typeof policy.product_label !== "string" ||
    policy.product_label === ""
  ) {
    return null;
  }
  return {
    channel: parsed.channel,
    github_latest: policy.github_latest,
    github_prerelease: policy.github_prerelease,
    product_label: policy.product_label,
    version: parsed.version,
  };
}

export function validateReleaseChannelContract(contract) {
  const expected = {
    alpha: { github_latest: false, github_prerelease: true },
    beta: { github_latest: false, github_prerelease: true },
    stable: { github_latest: true, github_prerelease: false },
  };
  const channels = contract.release_channels;
  if (
    channels === null ||
    typeof channels !== "object" ||
    Array.isArray(channels) ||
    JSON.stringify(Object.keys(channels).sort()) !==
      JSON.stringify(Object.keys(expected).sort())
  ) {
    return false;
  }
  for (const [name, required] of Object.entries(expected)) {
    const policy = channels[name];
    if (
      policy === null ||
      typeof policy !== "object" ||
      Array.isArray(policy) ||
      policy.github_latest !== required.github_latest ||
      policy.github_prerelease !== required.github_prerelease ||
      typeof policy.product_label !== "string" ||
      policy.product_label === "" ||
      policy.product_label.length > 64 ||
      [...policy.product_label].some((character) => {
        const codePoint = character.codePointAt(0);
        return codePoint <= 0x1f || codePoint === 0x7f;
      })
    ) {
      return false;
    }
  }
  return true;
}
