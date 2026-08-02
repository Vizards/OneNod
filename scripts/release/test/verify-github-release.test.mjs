import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const verifier = resolve(repositoryRoot, "scripts/release/verify-github-release.mjs");

const scenarios = [
  {
    channel: "stable",
    label: "Public Preview",
    name: "draft verification uses the authenticated Release list",
    prerelease: false,
    state: "draft",
    version: "0.0.1",
  },
  {
    channel: "beta",
    label: "Beta",
    name: "draft verification accepts an exactly classified beta Release",
    prerelease: true,
    state: "draft",
    version: "0.0.2-beta.1",
  },
  {
    channel: "stable",
    expectsLatest: true,
    label: "Public Preview",
    name: "published stable verification requires the repository latest Release",
    prerelease: false,
    state: "published",
    version: "0.0.2",
  },
  {
    channel: "beta",
    expectsLatest: false,
    label: "Beta",
    name: "published prerelease verification never queries the latest endpoint",
    prerelease: true,
    state: "published",
    version: "0.0.2-beta.2",
  },
];

for (const scenario of scenarios) {
  test(scenario.name, async () => {
    const fixture = await githubReleaseFixture(scenario);
    try {
      const result = verify(fixture, scenario);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, new RegExp(`"state":"${scenario.state}"`, "u"));
    } finally {
      await rm(fixture.root, { force: true, recursive: true });
    }
  });
}

async function githubReleaseFixture(scenario) {
  const root = await mkdtemp(join(tmpdir(), "onenod-github-verifier-"));
  const releaseDirectory = join(root, "release");
  const artifact = join(releaseDirectory, "artifact.txt");
  const mock = join(root, "mock-github.mjs");
  const content = `verified ${scenario.channel} ${scenario.state} asset\n`;
  const commit = scenario.channel === "stable" ? "a".repeat(40) : "b".repeat(40);
  await mkdir(releaseDirectory);
  await writeFile(artifact, content);
  await writeFile(
    mock,
    `const release = {
      id: 123,
      tag_name: process.env.TEST_TAG,
      draft: process.env.TEST_STATE === "draft",
      immutable: process.env.TEST_STATE === "published",
      prerelease: process.env.TEST_PRERELEASE === "true",
      name: process.env.TEST_RELEASE_NAME,
      published_at: process.env.TEST_STATE === "published"
        ? "2026-08-01T00:00:00Z"
        : null,
      assets: [{
        name: "artifact.txt",
        state: "uploaded",
        size: Number(process.env.TEST_ASSET_SIZE),
        digest: "sha256:" + process.env.TEST_ASSET_DIGEST,
      }],
    };
    globalThis.fetch = async (url) => {
      if (url.endsWith("/releases?per_page=100")) {
        return Response.json(release.draft ? [release] : []);
      }
      if (url.endsWith("/releases/latest")) {
        if (process.env.TEST_EXPECTS_LATEST !== "true") {
          throw new Error("prerelease verifier queried the latest endpoint");
        }
        return Response.json(release);
      }
      if (url.includes("/releases/tags/")) return Response.json(release);
      if (url.includes("/git/ref/tags/")) {
        return Response.json({ object: { type: "commit", sha: process.env.TEST_COMMIT } });
      }
      return new Response("not found", { status: 404 });
    };
`,
  );
  return {
    commit,
    content,
    mock,
    releaseDirectory,
    root,
  };
}

function verify(fixture, scenario) {
  const tag = `v${scenario.version}`;
  return spawnSync(
    process.execPath,
    [
      "--import",
      fixture.mock,
      verifier,
      "--directory",
      fixture.releaseDirectory,
      "--repository",
      "Vizards/OneNod",
      "--channel",
      scenario.channel,
      "--tag",
      tag,
      "--version",
      scenario.version,
      "--commit",
      fixture.commit,
      "--state",
      scenario.state,
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_TOKEN: "test-token",
        TEST_ASSET_DIGEST: createHash("sha256")
          .update(fixture.content)
          .digest("hex"),
        TEST_ASSET_SIZE: String(Buffer.byteLength(fixture.content)),
        TEST_COMMIT: fixture.commit,
        TEST_EXPECTS_LATEST: String(scenario.expectsLatest === true),
        TEST_PRERELEASE: String(scenario.prerelease),
        TEST_RELEASE_NAME: `OneNod ${tag} — ${scenario.label}`,
        TEST_STATE: scenario.state,
        TEST_TAG: tag,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
}
