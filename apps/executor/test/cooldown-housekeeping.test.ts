import assert from "node:assert/strict";
import test from "node:test";

import { runBestEffortCooldownUpdate } from "../src/cooldown-housekeeping.ts";

test("cooldown bookkeeping cannot replace an already-known operation result", () => {
  const reports: string[] = [];

  assert.doesNotThrow(() =>
    runBestEffortCooldownUpdate({
      operation: "credential.use",
      report: (message) => reports.push(message),
      stage: "record_success",
      update: () => {
        throw new Error("credential-value-must-not-appear");
      },
    }),
  );

  assert.equal(reports.length, 1);
  assert.deepEqual(JSON.parse(reports[0]!), {
    errorName: "Error",
    event: "executor_onepassword_cooldown_update_failed",
    operation: "credential.use",
    stage: "record_success",
  });
  assert.equal(reports[0]!.includes("credential-value-must-not-appear"), false);
});

test("cooldown diagnostics are also best effort and sanitize operation names", () => {
  assert.doesNotThrow(() =>
    runBestEffortCooldownUpdate({
      operation: "credential.use secret-value",
      report: () => {
        throw new Error("logging unavailable");
      },
      stage: "release_probe",
      update: () => {
        throw new Error("update unavailable");
      },
    }),
  );

  const reports: string[] = [];
  runBestEffortCooldownUpdate({
    operation: "credential.use secret-value",
    report: (message) => reports.push(message),
    stage: "release_probe",
    update: () => {
      throw new Error("update unavailable");
    },
  });
  assert.equal(JSON.parse(reports[0]!).operation, "unknown");
});
