import assert from "node:assert/strict";
import test from "node:test";

import { resolveGatewayRelease } from "../src/release.js";

const SOURCE_COMMIT = "b".repeat(40);

test("keeps candidate builds out of the development channel", () => {
  const release = resolveGatewayRelease({
    commit: SOURCE_COMMIT,
    tag: "v0.0.2-alpha.1",
    version: "0.0.2-alpha.1",
  });

  assert.equal(release.channel, "alpha");
  assert.equal(release.version, "0.0.2-alpha.1");
  assert.notEqual(release.tag, "dev");
});

test("fails closed when an injected channel disagrees with the version", () => {
  assert.throws(
    () =>
      resolveGatewayRelease({
        channel: "beta",
        commit: SOURCE_COMMIT,
        tag: "v0.0.2",
        version: "0.0.2",
      }),
    /gateway_release_channel_mismatch/u,
  );
});

test("fails closed on invalid or inconsistent injected release metadata", () => {
  assert.throws(
    () =>
      resolveGatewayRelease({
        commit: SOURCE_COMMIT,
        tag: "v1.2.3-rc.1",
        version: "1.2.3-rc.1",
      }),
    /invalid_gateway_release_version/u,
  );
  assert.throws(
    () =>
      resolveGatewayRelease({
        commit: SOURCE_COMMIT,
        tag: "v1.2.4",
        version: "1.2.3",
      }),
    /gateway_release_tag_mismatch/u,
  );
  assert.throws(
    () =>
      resolveGatewayRelease({
        commit: "not-a-commit",
        tag: "v1.2.3",
        version: "1.2.3",
      }),
    /invalid_gateway_source_commit/u,
  );
});
