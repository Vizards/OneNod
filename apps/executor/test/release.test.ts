import assert from "node:assert/strict";
import test from "node:test";

import { EXECUTOR_RELEASE } from "../src/release.ts";

test("development builds expose explicit non-release metadata", () => {
  assert.deepEqual(EXECUTOR_RELEASE, {
    sourceCommit: "unknown",
    tag: "dev",
    version: "0.0.0-dev",
  });
});
