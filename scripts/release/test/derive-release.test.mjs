import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const sourceScript = resolve(repositoryRoot, "scripts/release/derive-release.mjs");

test("the first public release is pinned to exactly 0.0.1", async () => {
  for (const candidate of ["0.1.0", "1.0.0"]) {
    const fixture = await releaseFixture(candidate);
    try {
      const result = runDerivation(fixture, "push");
      assert.notEqual(result.status, 0);
      assert.match(
        result.stderr,
        /first public release after the 0\.0\.0 baseline must be exactly 0\.0\.1/u,
      );

      const retry = runDerivation(fixture, "workflow_dispatch");
      assert.notEqual(retry.status, 0);
      assert.match(
        retry.stderr,
        /first public release after the 0\.0\.0 baseline must be exactly 0\.0\.1/u,
      );
    } finally {
      await rm(fixture.root, { force: true, recursive: true });
    }
  }
});

test("the exact 0.0.1 transition is releasable", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    const result = runDerivation(fixture, "push");
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.should_release, true);
    assert.equal(output.version, "0.0.1");
    assert.equal(output.previous_version, "");
    assert.equal(output.tag, "v0.0.1");
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("a manual retry runs from main but remains bound to the immutable tag", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    const result = runDerivation(fixture, "workflow_dispatch");
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.should_release, true);
    assert.equal(output.reason, "manual_retry");
    assert.equal(output.source_sha, fixture.releaseSha);
    assert.equal(output.tag, "v0.0.1");
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("a manual retry fails closed when the immutable tag is missing", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    git(fixture.root, ["tag", "-d", "v0.0.1"]);
    const result = runDerivation(fixture, "workflow_dispatch");
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /manual release retry requires existing immutable tag v0\.0\.1/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

async function releaseFixture(candidateVersion) {
  const root = await mkdtemp(join(tmpdir(), "onenod-derive-release-"));
  const script = join(root, "scripts/release/derive-release.mjs");
  await mkdir(dirname(script), { recursive: true });
  await writeFile(script, await readFile(sourceScript));
  await writeFile(
    join(root, "scripts/release/release-contract.json"),
    `${JSON.stringify({
      components: {
        keychain_helper: {
          source_digest: `sha256:${"a".repeat(64)}`,
          version: "1.0.0",
        },
      },
    })}\n`,
  );
  await writeFile(join(root, ".release-please-manifest.json"), '{".":"0.0.0"}\n');
  git(root, ["init", "-q"]);
  git(root, ["config", "user.email", "release-test@example.invalid"]);
  git(root, ["config", "user.name", "OneNod Release Test"]);
  git(root, ["config", "commit.gpgsign", "false"]);
  git(root, ["add", "."]);
  git(root, ["commit", "-qm", "chore: establish release baseline"]);
  await writeFile(
    join(root, ".release-please-manifest.json"),
    `${JSON.stringify({ ".": candidateVersion })}\n`,
  );
  git(root, ["add", ".release-please-manifest.json"]);
  git(root, ["commit", "-qm", `chore: release ${candidateVersion}`]);
  const releaseSha = git(root, ["rev-parse", "HEAD"]).trim();
  git(root, ["tag", `v${candidateVersion}`]);
  await writeFile(join(root, "trusted-workflow-revision"), "retry support\n");
  git(root, ["add", "trusted-workflow-revision"]);
  git(root, ["commit", "-qm", "fix: support release retries"]);
  const workflowSha = git(root, ["rev-parse", "HEAD"]).trim();
  return {
    candidateVersion,
    releaseSha,
    root,
    script,
    workflowSha,
  };
}

function runDerivation(fixture, event) {
  return spawnSync(
    process.execPath,
    [
      fixture.script,
      "--event",
      event,
      "--ref",
      "refs/heads/main",
      "--sha",
      event === "push" ? fixture.releaseSha : fixture.workflowSha,
      "--version-input",
      event === "push" ? "" : fixture.candidateVersion,
      "--output",
      "",
    ],
    {
      cwd: fixture.root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
}

function git(cwd, args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}
