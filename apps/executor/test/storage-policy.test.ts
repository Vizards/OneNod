import assert from "node:assert/strict";
import test from "node:test";

import {
  isSqliteFullError,
} from "../src/storage-policy.ts";

test("recognizes Cloudflare SQLite-full failures without broad error matching", () => {
  assert.equal(isSqliteFullError(new Error("SQLITE_FULL: database or disk is full")), true);
  assert.equal(isSqliteFullError({ code: "SQLITE_FULL" }), true);
  assert.equal(
    isSqliteFullError(new Error("outer", { cause: new Error("database or disk is full") })),
    true,
  );
  assert.equal(isSqliteFullError(new Error("constraint failed")), false);
});
