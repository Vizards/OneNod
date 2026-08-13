import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const sourceScript = resolve(repositoryRoot, "scripts/release/derive-release.mjs");
const sourceVersionHelper = resolve(
  repositoryRoot,
  "scripts/release/release-version.mjs",
);

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

test("a manual retry accepts reviewed same-version fixes after the manifest transition", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    git(fixture.root, ["tag", "-f", "v0.0.1", fixture.workflowSha]);
    const taggedRecoverySha = fixture.workflowSha;
    await writeFile(join(fixture.root, "trusted-retry-revision"), "retry derivation support\n");
    git(fixture.root, ["add", "trusted-retry-revision"]);
    git(fixture.root, ["commit", "-qm", "fix: derive retry from manifest history"]);
    fixture.workflowSha = git(fixture.root, ["rev-parse", "HEAD"]).trim();

    const result = runDerivation(fixture, "workflow_dispatch");
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.should_release, true);
    assert.equal(output.previous_version, "");
    assert.equal(output.source_sha, taggedRecoverySha);
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

test("an alpha release derives its version from a same-repository branch", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const candidateSha = await candidateCommit(fixture, "feature/alpha-one");
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: candidateSha,
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.channel, "alpha");
    assert.equal(output.github_prerelease, true);
    assert.equal(output.github_latest, false);
    assert.equal(output.artifact_predecessor_version, "0.0.1");
    assert.equal(output.previous_version, "0.0.1");
    assert.equal(output.helper_changed, false);
    assert.equal(output.version, "0.0.2-alpha.1");
    assert.equal(output.source_sha, candidateSha);
    assert.equal(output.reason, "derived_alpha");
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("the first alpha may bind the reviewed main commit itself", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: fixture.workflowSha,
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.version, "0.0.2-alpha.1");
    assert.equal(output.source_sha, fixture.workflowSha);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("new prereleases reject a caller-supplied version", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "beta",
      version: "0.0.2-alpha.1",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /new beta releases derive their version automatically/u);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("successive prereleases reuse the immediate predecessor helper bytes", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const firstCandidate = await candidateCommit(fixture, "feature/alpha-first");
    git(fixture.root, ["tag", "v0.0.2-alpha.1", firstCandidate]);
    const secondCandidate = await candidateCommit(fixture, "feature/alpha-second");

    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: secondCandidate,
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.version, "0.0.2-alpha.2");
    assert.equal(output.artifact_predecessor_version, "0.0.2-alpha.1");
    assert.equal(output.helper_changed, false);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("an active prerelease train blocks a different release core", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    git(fixture.root, ["tag", "v0.0.3-alpha.1", fixture.workflowSha]);
    await writeFile(
      join(fixture.root, ".release-please-manifest.json"),
      '{".":"0.0.2"}\n',
    );
    git(fixture.root, ["add", ".release-please-manifest.json"]);
    git(fixture.root, ["commit", "-qm", "chore: prepare stable 0.0.2"]);
    fixture.workflowSha = git(fixture.root, ["rev-parse", "HEAD"]).trim();
    fixture.releaseSha = fixture.workflowSha;

    const result = runDerivation(fixture, "push");
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /release train 0\.0\.3 must reach stable before starting 0\.0\.2/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("a candidate branch cannot replace the reviewed release policy", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    git(fixture.root, ["checkout", "-qb", "feature/policy-drift"]);
    const contractPath = join(
      fixture.root,
      "scripts/release/release-contract.json",
    );
    const contract = JSON.parse(await readFile(contractPath, "utf8"));
    contract.release_train.target_version = "0.0.3";
    await writeFile(contractPath, `${JSON.stringify(contract)}\n`);
    git(fixture.root, ["add", "scripts/release/release-contract.json"]);
    git(fixture.root, ["commit", "-qm", "chore: alter candidate release train"]);
    const candidateSha = git(fixture.root, ["rev-parse", "HEAD"]).trim();
    git(fixture.root, ["checkout", "-q", "main"]);
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: candidateSha,
    });
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /candidate release policy differs from the reviewed main policy/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("alpha rejects a source that does not contain the trusted main workflow", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: fixture.releaseSha,
    });
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /alpha source must contain the trusted main workflow commit/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("alpha rejects a detached candidate commit", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const candidateSha = await candidateCommit(fixture, "feature/detached");
    git(fixture.root, ["branch", "-D", "feature/detached"]);
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: candidateSha,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /reachable from a same-repository branch/u);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("beta is automatically numbered and bound to trusted main", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const alphaSha = await candidateCommit(fixture, "feature/accepted-alpha");
    git(fixture.root, ["tag", "v0.0.2-alpha.1", alphaSha]);
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "beta",
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.version, "0.0.2-beta.1");
    assert.equal(output.source_sha, fixture.workflowSha);
    assert.equal(output.artifact_predecessor_version, "0.0.2-alpha.1");
    assert.equal(output.reason, "derived_beta");
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("beta rejects a feature-branch source", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    const candidateSha = await candidateCommit(fixture, "feature/not-main-beta");
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "beta",
      sourceSha: candidateSha,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /derive their source from the trusted main/u);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("a release train cannot return to alpha after beta begins", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    git(fixture.root, ["tag", "v0.0.2-beta.1", fixture.workflowSha]);
    const candidateSha = await candidateCommit(fixture, "feature/late-alpha");
    const result = runDerivation(fixture, "workflow_dispatch", {
      intent: "alpha",
      sourceSha: candidateSha,
    });
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /new release 0\.0\.2-alpha\.1 must be newer than existing official tag v0\.0\.2-beta\.1/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("beta to stable separates support and artifact predecessors", async () => {
  const fixture = await releaseFixture("0.0.1");
  try {
    await advanceReleaseTrain(fixture, "0.0.2");
    git(fixture.root, ["tag", "v0.0.2-beta.1", fixture.workflowSha]);
    await writeFile(
      join(fixture.root, ".release-please-manifest.json"),
      '{".":"0.0.2"}\n',
    );
    git(fixture.root, ["add", ".release-please-manifest.json"]);
    git(fixture.root, ["commit", "-qm", "chore: release stable 0.0.2"]);
    fixture.releaseSha = git(fixture.root, ["rev-parse", "HEAD"]).trim();

    const result = runDerivation(fixture, "push");
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.previous_version, "0.0.1");
    assert.equal(output.artifact_predecessor_version, "0.0.2-beta.1");
    assert.equal(output.channel, "stable");
    assert.equal(output.release_train_target, "0.0.2");
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
    join(root, "scripts/release/release-version.mjs"),
    await readFile(sourceVersionHelper),
  );
  await symlink(resolve(repositoryRoot, "node_modules"), join(root, "node_modules"));
  await writeFile(
    join(root, "scripts/release/release-contract.json"),
    `${JSON.stringify({
      components: {
        keychain_helper: {
          source_digest: `sha256:${"a".repeat(64)}`,
          version: "1.0.0",
        },
      },
      release_train: { target_version: candidateVersion },
      release_channels: {
        alpha: {
          github_latest: false,
          github_prerelease: true,
          product_label: "Alpha",
        },
        beta: {
          github_latest: false,
          github_prerelease: true,
          product_label: "Beta",
        },
        stable: {
          github_latest: true,
          github_prerelease: false,
          product_label: "Public Preview",
        },
      },
    })}\n`,
  );
  await writeFile(join(root, ".release-please-manifest.json"), '{".":"0.0.0"}\n');
  git(root, ["init", "-q"]);
  git(root, ["branch", "-M", "main"]);
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

async function advanceReleaseTrain(fixture, targetVersion) {
  const contractPath = join(
    fixture.root,
    "scripts/release/release-contract.json",
  );
  const contract = JSON.parse(await readFile(contractPath, "utf8"));
  contract.release_train.target_version = targetVersion;
  await writeFile(contractPath, `${JSON.stringify(contract)}\n`);
  git(fixture.root, ["add", "scripts/release/release-contract.json"]);
  git(fixture.root, ["commit", "-qm", `chore: open release train ${targetVersion}`]);
  fixture.workflowSha = git(fixture.root, ["rev-parse", "HEAD"]).trim();
}

async function candidateCommit(fixture, branch) {
  git(fixture.root, ["checkout", "-qb", branch, fixture.workflowSha]);
  const marker = branch.replaceAll("/", "-");
  await writeFile(join(fixture.root, marker), `${branch}\n`);
  git(fixture.root, ["add", marker]);
  git(fixture.root, ["commit", "-qm", `test: create ${branch}`]);
  const sourceSha = git(fixture.root, ["rev-parse", "HEAD"]).trim();
  git(fixture.root, ["checkout", "-q", "main"]);
  return sourceSha;
}

function runDerivation(fixture, event, overrides = {}) {
  const intent = overrides.intent ?? (event === "workflow_dispatch" ? "retry" : "");
  const version =
    overrides.version ??
    (event === "workflow_dispatch" && intent === "retry"
      ? fixture.candidateVersion
      : "");
  const sourceSha =
    overrides.sourceSha ??
    (event === "workflow_dispatch" && intent === "alpha"
      ? fixture.workflowSha
      : "");
  return spawnSync(
    process.execPath,
    [
      fixture.script,
      "--event",
      event,
      "--intent",
      intent,
      "--ref",
      "refs/heads/main",
      "--sha",
      event === "push" ? fixture.releaseSha : fixture.workflowSha,
      "--source-sha",
      sourceSha,
      "--version-input",
      version,
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
