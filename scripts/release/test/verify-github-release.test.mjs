import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const verifier = resolve(repositoryRoot, "scripts/release/verify-github-release.mjs");

test("draft verification uses the authenticated Release list", async () => {
  const root = await mkdtemp(join(tmpdir(), "onenod-draft-verifier-"));
  const releaseDirectory = join(root, "release");
  const artifact = join(releaseDirectory, "artifact.txt");
  const mock = join(root, "mock-github.mjs");
  const content = "verified draft asset\n";
  const commit = "a".repeat(40);
  await mkdir(releaseDirectory);
  await writeFile(artifact, content);
  await writeFile(
    mock,
    `globalThis.fetch = async (url) => {
      if (url.endsWith("/releases?per_page=100")) {
        return Response.json([{
          tag_name: "v0.0.1", draft: true, immutable: false,
          prerelease: false, name: "OneNod v0.0.1 — Public Preview",
          assets: [{
            name: "artifact.txt", state: "uploaded",
            size: Number(process.env.TEST_ASSET_SIZE),
            digest: "sha256:" + process.env.TEST_ASSET_DIGEST,
          }],
        }]);
      }
      if (url.includes("/git/ref/tags/")) {
        return Response.json({ object: { type: "commit", sha: process.env.TEST_COMMIT } });
      }
      return new Response("not found", { status: 404 });
    };
`,
  );
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import", mock, verifier,
        "--directory", releaseDirectory,
        "--repository", "Vizards/OneNod",
        "--tag", "v0.0.1",
        "--commit", commit,
        "--state", "draft",
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_TOKEN: "test-token",
          TEST_ASSET_DIGEST: createHash("sha256").update(content).digest("hex"),
          TEST_ASSET_SIZE: String(Buffer.byteLength(content)),
          TEST_COMMIT: commit,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"state":"draft"/u);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});
