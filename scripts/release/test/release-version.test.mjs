import assert from "node:assert/strict";
import test from "node:test";

import {
  compareProductVersions,
  parseProductVersion,
  parseStableVersion,
  productVersionCore,
  releaseChannelPolicy,
  releaseMatchesTrain,
  releaseTrainTarget,
  releaseUpgradeVersionPolicy,
  validateReleaseChannelContract,
} from "../release-version.mjs";

const contract = {
  release_train: { target_version: "1.2.3" },
  release_channels: {
    alpha: {
      github_latest: false,
      github_prerelease: true,
      product_label: "Alpha",
    },
    beta: {
      github_latest: false,
      github_prerelease: true,
      product_label: "Beta",
    },
    stable: {
      github_latest: true,
      github_prerelease: false,
      product_label: "Public Preview",
    },
  },
};

test("product versions accept only stable, alpha.N, and beta.N", () => {
  assert.deepEqual(parseProductVersion("1.2.3"), {
    channel: "stable",
    version: "1.2.3",
  });
  assert.deepEqual(parseProductVersion("1.2.3-alpha.1"), {
    channel: "alpha",
    version: "1.2.3-alpha.1",
  });
  assert.deepEqual(parseProductVersion("1.2.3-beta.12"), {
    channel: "beta",
    version: "1.2.3-beta.12",
  });
  assert.deepEqual(parseStableVersion("1.2.3"), {
    channel: "stable",
    version: "1.2.3",
  });
  assert.equal(parseStableVersion("1.2.3-beta.1"), null);

  for (const value of [
    "v1.2.3",
    "1.2.3-alpha",
    "1.2.3-alpha.0",
    "1.2.3-alpha.01",
    "1.2.3-beta.0",
    "1.2.3-rc.1",
    "1.2.3-alpha.1+build",
    "01.2.3",
    "1.2.3.4",
  ]) {
    assert.equal(parseProductVersion(value), null, value);
  }
});

test("product versions use canonical SemVer precedence", () => {
  const versions = [
    "1.2.3",
    "1.2.3-beta.2",
    "1.2.3-alpha.10",
    "1.2.3-beta.1",
    "1.2.3-alpha.2",
  ];
  assert.deepEqual(versions.sort(compareProductVersions), [
    "1.2.3-alpha.2",
    "1.2.3-alpha.10",
    "1.2.3-beta.1",
    "1.2.3-beta.2",
    "1.2.3",
  ]);
});

test("release generation accepts only an already-released exact bridge updater", () => {
  assert.equal(
    releaseUpgradeVersionPolicy(
      {
        minimum_safe_version: "0.0.1",
        minimum_updater_version: "0.0.2-alpha.26",
      },
      "0.0.2-alpha.27",
    ),
    null,
  );
  assert.match(
    releaseUpgradeVersionPolicy(
      {
        minimum_safe_version: "0.0.1",
        minimum_updater_version: "0.0.2-alpha.28",
      },
      "0.0.2-alpha.27",
    ),
    /cannot exceed/u,
  );
  for (const invalid of ["0.0.2-rc.1", "0.0.2-alpha", "not-a-version"]) {
    assert.match(
      releaseUpgradeVersionPolicy(
        {
          minimum_safe_version: "0.0.1",
          minimum_updater_version: invalid,
        },
        "0.0.2-alpha.27",
      ),
      /must be a product version/u,
      invalid,
    );
  }
});

test("a reviewed release train binds every new channel to one core", () => {
  assert.equal(releaseTrainTarget(contract), "1.2.3");
  assert.equal(productVersionCore("1.2.3-alpha.4"), "1.2.3");
  assert.equal(releaseMatchesTrain(contract, "1.2.3-alpha.4"), true);
  assert.equal(releaseMatchesTrain(contract, "1.2.3-beta.1"), true);
  assert.equal(releaseMatchesTrain(contract, "1.2.3"), true);
  assert.equal(releaseMatchesTrain(contract, "1.2.4-alpha.1"), false);
  assert.equal(
    releaseTrainTarget({ release_train: { target_version: "1.2.3-alpha.1" } }),
    null,
  );
});

test("the release contract is the sole channel policy", () => {
  assert.equal(validateReleaseChannelContract(contract), true);
  assert.deepEqual(releaseChannelPolicy(contract, "1.2.3-beta.4"), {
    channel: "beta",
    github_latest: false,
    github_prerelease: true,
    product_label: "Beta",
    version: "1.2.3-beta.4",
  });
  assert.equal(
    validateReleaseChannelContract({
      ...contract,
      release_channels: {
        ...contract.release_channels,
        stable: {
          ...contract.release_channels.stable,
          github_prerelease: true,
        },
      },
    }),
    false,
  );
});
