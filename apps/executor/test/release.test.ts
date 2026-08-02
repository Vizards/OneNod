import assert from "node:assert/strict";
import test from "node:test";

import {
  EXECUTOR_RELEASE,
  resolveExecutorRelease,
} from "../src/release.ts";

const SOURCE_COMMIT = "a".repeat(40);

test("development builds expose explicit non-release metadata", () => {
  assert.deepEqual(EXECUTOR_RELEASE, {
    channel: "dev",
    sourceCommit: "unknown",
    tag: "dev",
    version: "0.0.0-dev",
  });
});

test("does not downgrade candidate versions to development metadata", () => {
  const release = resolveExecutorRelease({
    commit: SOURCE_COMMIT,
    tag: "v0.0.2-beta.1",
    version: "0.0.2-beta.1",
  });

  assert.equal(release.channel, "beta");
  assert.equal(release.version, "0.0.2-beta.1");
  assert.notEqual(release.tag, "dev");
});

test("fails closed when an injected channel disagrees with the version", () => {
  assert.throws(
    () =>
      resolveExecutorRelease({
        channel: "stable",
        commit: SOURCE_COMMIT,
        tag: "v0.0.2-alpha.1",
        version: "0.0.2-alpha.1",
      }),
    /executor_release_channel_mismatch/u,
  );
});

test("fails closed on invalid or incomplete injected release metadata", () => {
  assert.throws(
    () =>
      resolveExecutorRelease({
        commit: SOURCE_COMMIT,
        tag: "v1.2.3-rc.1",
        version: "1.2.3-rc.1",
      }),
    /invalid_executor_release_version/u,
  );
  assert.throws(
    () =>
      resolveExecutorRelease({
        commit: SOURCE_COMMIT,
        tag: "v1.2.4",
        version: "1.2.3",
      }),
    /executor_release_tag_mismatch/u,
  );
  assert.throws(
    () =>
      resolveExecutorRelease({
        commit: "not-a-commit",
        tag: "v1.2.3",
        version: "1.2.3",
      }),
    /invalid_executor_source_commit/u,
  );
  assert.throws(
    () => resolveExecutorRelease({ channel: "alpha" }),
    /incomplete_executor_release_metadata/u,
  );
});
