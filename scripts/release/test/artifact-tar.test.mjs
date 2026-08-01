import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import tar from "tar-stream";

import {
  readArtifactArchive,
  writeArtifactArchive,
} from "../artifact-tar.mjs";

const fixedHeader = {
  gid: 0,
  gname: "root",
  mode: 0o644,
  mtime: new Date(0),
  type: "file",
  uid: 0,
  uname: "root",
};

test("artifact tar output is canonical and deterministic", async () => {
  const directory = await mkdtemp(join(tmpdir(), "onenod-artifact-tar-test-"));
  const first = join(directory, "first.tar.gz");
  const second = join(directory, "second.tar.gz");
  const entries = [
    { content: Buffer.from("second\n"), mode: 0o644, name: "onenod/z.txt" },
    { content: Buffer.from("first\n"), mode: 0o755, name: "onenod/bin/may" },
  ];
  try {
    await writeArtifactArchive(first, entries);
    await writeArtifactArchive(second, [...entries].reverse());
    assert.equal(await digest(first), await digest(second));

    const archive = await readArtifactArchive(first);
    assert.deepEqual([...archive.files.keys()], ["onenod/bin/may", "onenod/z.txt"]);
    assert.equal(archive.files.get("onenod/bin/may")?.content.toString(), "first\n");
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("artifact tar reader rejects unsafe structure, metadata, and extensions", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "onenod-artifact-tar-test-"));
  const fixtures = {
    "absolute path": [{ name: "/onenod/file" }],
    "block device": [{ name: "onenod/device", type: "block-device" }],
    "different roots": [{ name: "onenod/a" }, { name: "other/b" }],
    "directory entry": [{ name: "onenod/directory", type: "directory" }],
    "duplicate path": [{ name: "onenod/file" }, { name: "onenod/file" }],
    "embedded NUL": [{ name: "onenod/file\u0000hidden" }],
    "hard link": [{ linkname: "onenod/target", name: "onenod/link", type: "link" }],
    "non-canonical metadata": [{ mode: 0o600, name: "onenod/file", uid: 501 }],
    "PAX extension": [{ name: "onenod/file", pax: { comment: "unexpected" } }],
    "path traversal": [{ name: "onenod/../outside" }],
    "symbolic link": [
      { linkname: "onenod/target", name: "onenod/link", type: "symlink" },
    ],
    "unsorted entries": [{ name: "onenod/z" }, { name: "onenod/a" }],
  };
  try {
    for (const [name, entries] of Object.entries(fixtures)) {
      await t.test(name, async () => {
        const path = join(directory, `${name.replaceAll(" ", "-")}.tar.gz`);
        await writeRawArchive(path, entries);
        await assert.rejects(
          readArtifactArchive(path),
          /release_archive_failed:/u,
        );
      });
    }

    const invalidGzip = join(directory, "invalid-gzip.tar.gz");
    await writeFile(invalidGzip, "not a gzip stream");
    await assert.rejects(
      readArtifactArchive(invalidGzip),
      /not a valid bounded gzip stream/u,
    );

    const incompleteTar = join(directory, "incomplete-tar.tar.gz");
    await writeFile(incompleteTar, gzipSync(Buffer.alloc(512), { mtime: 0 }));
    await assert.rejects(
      readArtifactArchive(incompleteTar),
      /release archive contains no regular files/u,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("artifact tar writer rejects extended paths and excessive entry counts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "onenod-artifact-tar-test-"));
  try {
    for (const name of [
      "onenod/雪.txt",
      `onenod/${"a".repeat(256)}`,
      "file-without-root",
    ]) {
      await assert.rejects(
        writeArtifactArchive(join(directory, `${createHash("sha1").update(name).digest("hex")}.tar.gz`), [
          { content: Buffer.from("fixture"), mode: 0o644, name },
        ]),
        /release_archive_failed:/u,
      );
    }
    await assert.rejects(
      writeArtifactArchive(
        join(directory, "too-many.tar.gz"),
        Array.from({ length: 4_097 }, (_, index) => ({
          content: Buffer.alloc(0),
          mode: 0o644,
          name: `onenod/${index.toString().padStart(4, "0")}`,
        })),
      ),
      /too many entries/u,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

async function writeRawArchive(path, entries) {
  const pack = tar.pack();
  const chunks = [];
  pack.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
  const completion = new Promise((resolve, reject) => {
    pack.once("end", resolve);
    pack.once("error", reject);
  });
  for (const entry of entries) await addRawEntry(pack, entry);
  pack.finalize();
  await completion;
  await writeFile(path, gzipSync(Buffer.concat(chunks), { level: 9, mtime: 0 }));
}

function addRawEntry(pack, fixture) {
  const header = { ...fixedHeader, ...fixture };
  const content = Buffer.from("fixture");
  return new Promise((resolve, reject) => {
    if (header.type === "file") {
      pack.entry(header, content, (error) => (error ? reject(error) : resolve()));
      return;
    }
    const entry = pack.entry(header, (error) =>
      error ? reject(error) : resolve(),
    );
    entry.end();
  });
}

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}
