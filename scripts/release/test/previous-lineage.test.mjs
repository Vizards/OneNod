import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const verifier = resolve(
  repositoryRoot,
  "scripts/release/verify-previous-lineage.mjs",
);
const version = "0.0.1";
const commit = "a".repeat(40);

test("a published immutable predecessor is bound to its tag commit", async () => {
  const fixture = await lineageFixture();
  try {
    const valid = verify(fixture);
    assert.equal(valid.status, 0, valid.stderr);

    const release = JSON.parse(await fixture.releaseText());
    release.immutable = false;
    await writeFile(fixture.release, `${JSON.stringify(release)}\n`);
    const mutable = verify(fixture);
    assert.notEqual(mutable.status, 0);
    assert.match(mutable.stderr, /not published, correctly classified, and immutable/u);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("an immutable beta Release is a valid artifact predecessor", async () => {
  const fixture = await lineageFixture({
    channel: "beta",
    prerelease: true,
    version: "0.0.2-beta.3",
  });
  try {
    const valid = verify(fixture);
    assert.equal(valid.status, 0, valid.stderr);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("the predecessor manifest must match immutable asset metadata and source", async () => {
  const fixture = await lineageFixture();
  try {
    const manifest = JSON.parse(await fixture.manifestText());
    manifest.source.commit = "b".repeat(40);
    await writeFile(fixture.manifest, `${JSON.stringify(manifest)}\n`);
    const tampered = verify(fixture);
    assert.notEqual(tampered.status, 0);
    assert.match(tampered.stderr, /differs from immutable asset metadata/u);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

async function lineageFixture(overrides = {}) {
  const fixtureVersion = overrides.version ?? version;
  const channel = overrides.channel ?? "stable";
  const prerelease = overrides.prerelease ?? false;
  const root = await mkdtemp(join(tmpdir(), "onenod-lineage-test-"));
  const manifestPath = join(root, "release-manifest.json");
  const releasePath = join(root, "release.json");
  const manifestText = `${JSON.stringify({
    channel,
    release_version: fixtureVersion,
    schema_version: 1,
    source: {
      commit,
      repository: "Vizards/OneNod",
      workflow: ".github/workflows/release.yml",
    },
    tag: `v${fixtureVersion}`,
  })}\n`;
  await writeFile(manifestPath, manifestText);
  const digest = `sha256:${createHash("sha256").update(manifestText).digest("hex")}`;
  const releaseText = `${JSON.stringify({
    assets: [
      {
        digest,
        name: "release-manifest.json",
        size: Buffer.byteLength(manifestText),
        state: "uploaded",
      },
    ],
    draft: false,
    id: 123,
    immutable: true,
    prerelease,
    published_at: "2026-08-01T00:00:00Z",
    tag_name: `v${fixtureVersion}`,
  })}\n`;
  await writeFile(releasePath, releaseText);
  return {
    manifest: manifestPath,
    manifestText: () => readText(manifestPath),
    release: releasePath,
    releaseText: () => readText(releasePath),
    root,
    version: fixtureVersion,
  };
}

function verify(fixture) {
  return spawnSync(
    process.execPath,
    [
      verifier,
      "--release",
      fixture.release,
      "--manifest",
      fixture.manifest,
      "--version",
      fixture.version,
      "--commit",
      commit,
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
}

async function readText(path) {
  return readFile(path, "utf8");
}
