import assert from "node:assert/strict";
import test from "node:test";

import { ExecutionJournalError } from "../src/execution-journal.ts";
import { classifyExecutorFailure } from "../src/executor-failure.ts";
import { ExecutorRequestError } from "../src/executor-request-error.ts";
import { GatewayOperationError } from "../src/onepassword-raw-gateway.ts";

test("only explicit request validation failures become 400 responses", () => {
  const catalog = classifyExecutorFailure(
    new ExecutorRequestError("request_fields_invalid"),
    "/internal/1password/catalog",
  );
  const item = classifyExecutorFailure(
    new ExecutorRequestError("request_fields_invalid"),
    "/internal/1password/secret/read",
  );
  const ssh = classifyExecutorFailure(
    new ExecutorRequestError("request_fields_invalid"),
    "/internal/1password/ssh/sign",
  );

  assert.deepEqual(
    [catalog.error.code, catalog.error.status, catalog.kind],
    ["catalog_query_invalid", 400, "request-validation"],
  );
  assert.deepEqual(
    [item.error.code, item.error.status, item.kind],
    ["item_operation_invalid", 400, "request-validation"],
  );
  assert.deepEqual(
    [ssh.error.code, ssh.error.status, ssh.kind],
    ["ssh_sign_request_invalid", 400, "request-validation"],
  );
});

test("unexpected implementation and SQLite failures are not mislabeled as bad requests", () => {
  const internal = classifyExecutorFailure(
    new TypeError("post-operation housekeeping failed"),
    "/internal/1password/secret/read",
  );
  const storage = classifyExecutorFailure(
    new Error("SQLITE_FULL: database or disk is full"),
    "/internal/1password/secret/read",
  );

  assert.deepEqual(
    [internal.error.code, internal.error.status, internal.kind],
    ["executor_internal_error", 503, "unexpected-internal"],
  );
  assert.equal(internal.errorName, "TypeError");
  assert.deepEqual(
    [storage.error.code, storage.error.status, storage.kind],
    ["executor_storage_pressure", 507, "storage-pressure"],
  );
});

test("known operation and journal pressure errors keep their stable classification", () => {
  const knownError = new GatewayOperationError("field_not_found", 404);
  const known = classifyExecutorFailure(
    knownError,
    "/internal/1password/secret/read",
  );
  const journal = classifyExecutorFailure(
    new ExecutionJournalError("journal_storage_pressure"),
    "/internal/1password/item/mutate",
  );

  assert.equal(known.error, knownError);
  assert.equal(known.kind, "known-operation");
  assert.deepEqual(
    [journal.error.code, journal.error.status, journal.kind],
    ["executor_storage_pressure", 507, "storage-pressure"],
  );
});
