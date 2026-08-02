import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { validateReleaseWorkflow } from "../release-workflow-contract.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const workflow = await readFile(
  resolve(repositoryRoot, ".github/workflows/release.yml"),
  "utf8",
);

test("the current release workflow satisfies the structured contract", () => {
  assert.doesNotThrow(() => validateReleaseWorkflow(workflow));
});

test("a comment cannot disguise a non-frozen dependency install", () => {
  const changed = replaceOnce(
    workflow,
    "        run: pnpm install --frozen-lockfile\n",
    [
      "        run: pnpm install --frozen-lockfile=false",
      "        # run: pnpm install --frozen-lockfile",
      "",
    ].join("\n"),
  );
  assert.throws(
    () => validateReleaseWorkflow(changed),
    /does not install the frozen Node dependency set/u,
  );
});

test("release retries retain the environment for their derived channel", () => {
  const changed = replaceOnce(
    workflow,
    "      name: release-${{ needs.prepare.outputs.channel }}",
    "      name: release-retry",
  );
  assert.throws(
    () => validateReleaseWorkflow(changed),
    /authorize job must gate and bind/u,
  );
});

test("prepare verifies the exact selected source before authorization", () => {
  const changed = replaceOnce(
    workflow,
    '        run: node scripts/release/verify-source-contract.mjs --source-sha "$SOURCE_SHA"',
    "        run: echo source contract skipped",
  );
  assert.throws(
    () => validateReleaseWorkflow(changed),
    /prepare job must produce a read-only, signed-source plan/u,
  );
});

function replaceOnce(value, before, after) {
  const changed = value.replace(before, after);
  assert.notEqual(changed, value, `fixture text is missing: ${before}`);
  return changed;
}
