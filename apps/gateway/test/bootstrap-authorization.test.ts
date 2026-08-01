import assert from "node:assert/strict";
import test from "node:test";

import {
  bootstrapTokensMatch,
} from "../src/worker/bootstrap-authorization.js";

test("bootstrap token comparison accepts any non-empty exact Secret value", async () => {
  assert.equal(await bootstrapTokensMatch("a", "a"), true);
  assert.equal(await bootstrapTokensMatch("setup code", "setup code"), true);
  assert.equal(await bootstrapTokensMatch("a\n", "a\n"), true);
  assert.equal(await bootstrapTokensMatch("a", "b"), false);
  assert.equal(await bootstrapTokensMatch("", ""), false);
  assert.equal(await bootstrapTokensMatch(undefined, "a"), false);
});
