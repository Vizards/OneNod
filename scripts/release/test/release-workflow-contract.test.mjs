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

test("candidate numbering cannot promote an unpublished tag into release lineage", () => {
  const changed = replaceOnce(
    workflow,
    "select(.draft == false and .immutable == true)",
    "select(.draft == false)",
  );
  assert.throws(
    () => validateReleaseWorkflow(changed),
    /read-only, signed-source plan/u,
  );
});

test("published lineage inventory remains complete and versioned", () => {
  for (const [before, after] of [
    ["gh api --paginate --slurp", "gh api --slurp"],
    ["X-GitHub-Api-Version: 2026-03-10", "X-GitHub-Api-Version: 2022-11-28"],
    [".draft == false and .immutable == true", ".immutable == true"],
    [
      '> "$RUNNER_TEMP/published-release-tags.json"',
      '> "$RUNNER_TEMP/wrong-release-tags.json"',
    ],
  ]) {
    const changed = replaceOnce(workflow, before, after);
    assert.throws(
      () => validateReleaseWorkflow(changed),
      /read-only, signed-source plan/u,
    );
  }
});

test("the predecessor must retain official main-workflow provenance", () => {
  for (const [before, after] of [
    ["gh attestation verify", "echo attestation skipped"],
    [
      '--bundle "$lineage_dir/onenod-provenance.intoto.jsonl"',
      '--bundle "$lineage_dir/untrusted-provenance.intoto.jsonl"',
    ],
    [
      "--predicate-type https://slsa.dev/provenance/v1",
      "--predicate-type https://example.invalid/untrusted/v1",
    ],
    [
      "--signer-workflow github.com/Vizards/OneNod/.github/workflows/release.yml",
      "--signer-workflow github.com/example/fork/.github/workflows/release.yml",
    ],
    ["--source-ref refs/heads/main", "--source-ref refs/heads/untrusted"],
    ["--deny-self-hosted-runners", "--format json"],
  ]) {
    const changed = replaceOnce(workflow, before, after);
    assert.throws(
      () => validateReleaseWorkflow(changed),
      /read-only, signed-source plan/u,
    );
  }
});

test("native artifacts cannot silently lose exact-build signing", () => {
  const changed = workflow.replaceAll("              --options runtime \\\n", "");
  assert.notEqual(changed, workflow);
  assert.throws(
    () => validateReleaseWorkflow(changed),
    /must bind and verify deterministic ad-hoc Hardened Runtime exact builds/u,
  );
});

function replaceOnce(value, before, after) {
  const changed = value.replace(before, after);
  assert.notEqual(changed, value, `fixture text is missing: ${before}`);
  return changed;
}
