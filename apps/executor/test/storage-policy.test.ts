import assert from "node:assert/strict";
import test from "node:test";

import {
  EXECUTOR_CONSERVATIVE_DATABASE_BYTES,
  EXECUTOR_STORAGE_CRITICAL_BYTES,
  EXECUTOR_STORAGE_WARNING_BYTES,
  executorStoragePressure,
  isSqliteFullError,
} from "../src/storage-policy.ts";

test("uses conservative one-gigabyte 50/80 storage watermarks", () => {
  assert.equal(EXECUTOR_CONSERVATIVE_DATABASE_BYTES, 1_000_000_000);
  assert.equal(EXECUTOR_STORAGE_WARNING_BYTES, 500_000_000);
  assert.equal(EXECUTOR_STORAGE_CRITICAL_BYTES, 800_000_000);
  assert.equal(executorStoragePressure(EXECUTOR_STORAGE_WARNING_BYTES - 1), "normal");
  assert.equal(executorStoragePressure(EXECUTOR_STORAGE_WARNING_BYTES), "warning");
  assert.equal(executorStoragePressure(EXECUTOR_STORAGE_CRITICAL_BYTES), "critical");
  assert.equal(executorStoragePressure(Number.NaN), "critical");
});

test("recognizes Cloudflare SQLite-full failures without broad error matching", () => {
  assert.equal(isSqliteFullError(new Error("SQLITE_FULL: database or disk is full")), true);
  assert.equal(isSqliteFullError({ code: "SQLITE_FULL" }), true);
  assert.equal(
    isSqliteFullError(new Error("outer", { cause: new Error("database or disk is full") })),
    true,
  );
  assert.equal(isSqliteFullError(new Error("constraint failed")), false);
});
