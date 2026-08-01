import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { buffer } from "node:stream/consumers";
import { gzipSync, gunzipSync } from "node:zlib";

import tar from "tar-stream";

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 4_096;
const MAX_ENTRY_BYTES = 256 * 1024 * 1024;
const MAX_EXTRACTED_BYTES = 256 * 1024 * 1024;
const MAX_TAR_BYTES =
  MAX_EXTRACTED_BYTES + MAX_ARCHIVE_ENTRIES * 1_024 + 1_024;
const FIXED_MTIME = new Date(0);
const REGULAR_MODES = new Set([0o644, 0o755]);

export async function readArtifactArchive(path) {
  const info = await lstat(path).catch(() => null);
  if (
    info === null ||
    !info.isFile() ||
    info.size <= 0 ||
    info.size > MAX_ARCHIVE_BYTES
  ) {
    fail("artifact must be a bounded regular file");
  }
  const compressed = await readFile(path);
  const archiveSha256 = sha256(compressed);
  let tarBytes;
  try {
    tarBytes = gunzipSync(compressed, { maxOutputLength: MAX_TAR_BYTES });
  } catch {
    fail("artifact is not a valid bounded gzip stream");
  }
  const files = new Map();
  let extractedBytes = 0;
  let lastName = "";
  let nextHeaderOffset = 0;
  let root = "";
  const extract = tar.extract();
  extract.end(tarBytes);
  try {
    for await (const stream of extract) {
      const header = stream.header;
      validateRegularHeader(header);
      if (header.byteOffset !== nextHeaderOffset + 512) {
        fail("release archive contains an extended or hidden header");
      }
      rejectHiddenHeaderText(tarBytes, header.byteOffset - 512);
      const entryRoot = validateArchivePath(header.name);
      if (root === "") root = entryRoot;
      if (root !== entryRoot) fail("release archive must contain one root directory");
      if (lastName !== "" && header.name <= lastName) {
        fail("release archive entries are not deterministically sorted");
      }
      if (files.size >= MAX_ARCHIVE_ENTRIES) {
        fail("release archive contains too many entries");
      }
      if (files.has(header.name)) {
        fail(`unsafe or duplicate archive path: ${header.name}`);
      }
      if (header.size > MAX_EXTRACTED_BYTES - extractedBytes) {
        fail("release archive expands beyond the total size limit");
      }
      const content = await buffer(stream);
      if (content.byteLength !== header.size) {
        fail("release archive entry size differs from its header");
      }
      extractedBytes += content.byteLength;
      files.set(header.name, {
        bytes: content.byteLength,
        content,
        sha1: createHash("sha1").update(content).digest("hex"),
        sha256: sha256(content),
      });
      lastName = header.name;
      nextHeaderOffset = header.byteOffset + Math.ceil(header.size / 512) * 512;
    }
  } catch (error) {
    if (isReleaseArchiveError(error)) throw error;
    fail("artifact is not a valid tar archive");
  }
  if (files.size === 0) fail("release archive contains no regular files");
  if (tarBytes.byteLength !== nextHeaderOffset + 1_024) {
    fail("release archive is not in the canonical deterministic tar form");
  }
  return { archiveSha256, files };
}

export async function writeArtifactArchive(path, entries) {
  const canonicalEntries = normalizeEntries(entries);
  const tarBytes = await packEntries(canonicalEntries);
  let compressed;
  try {
    compressed = gzipSync(tarBytes, { level: 9, mtime: 0 });
  } catch {
    fail("could not create the release gzip stream");
  }
  if (compressed.byteLength > MAX_ARCHIVE_BYTES) {
    fail("compressed release archive exceeds the size limit");
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await writeFile(path, compressed, { flag: "wx", mode: 0o644 });
}

export function readArtifactIdentity(files) {
  const releaseEntries = [...files.entries()].filter(([name]) =>
    name.endsWith("/RELEASE.json"),
  );
  if (releaseEntries.length !== 1) {
    fail("release archive must carry exactly one RELEASE.json");
  }
  let descriptor;
  try {
    descriptor = JSON.parse(releaseEntries[0][1].content.toString("utf8"));
  } catch {
    fail("release archive has an invalid RELEASE.json");
  }
  if (
    descriptor === null ||
    typeof descriptor !== "object" ||
    Array.isArray(descriptor) ||
    descriptor.schema_version !== 1 ||
    descriptor.repository !== "Vizards/OneNod" ||
    typeof descriptor.source_commit !== "string" ||
    !/^[0-9a-f]{40}$/u.test(descriptor.source_commit)
  ) {
    fail("release archive identity is invalid");
  }
  const kind = descriptor.artifact_kind;
  const roots = {
    deployment: "onenod-deployment/RELEASE.json",
    keychain_helper: "onenod-keychain-helper/RELEASE.json",
    local: "onenod/RELEASE.json",
    skill: "onenod-skill/RELEASE.json",
  };
  if (typeof kind !== "string" || roots[kind] !== releaseEntries[0][0]) {
    fail("release archive kind differs from its archive root");
  }
  const helper = kind === "keychain_helper";
  const version = helper ? descriptor.helper_version : descriptor.release_version;
  if (
    typeof version !== "string" ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(version)
  ) {
    fail("release archive has no stable component version");
  }
  let helperProtocol;
  let helperSourceDigest;
  if (helper) {
    helperProtocol = descriptor.helper_protocol;
    helperSourceDigest = descriptor.helper_source_digest;
    if (
      !Number.isSafeInteger(helperProtocol) ||
      helperProtocol <= 0 ||
      typeof helperSourceDigest !== "string" ||
      !/^sha256:[0-9a-f]{64}$/u.test(helperSourceDigest)
    ) {
      fail("Keychain helper archive identity is invalid");
    }
  }
  return {
    helperProtocol,
    helperSourceDigest,
    kind,
    sourceCommit: descriptor.source_commit,
    version,
  };
}

function normalizeEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    fail("release archive contains no regular files");
  }
  if (entries.length > MAX_ARCHIVE_ENTRIES) {
    fail("release archive contains too many entries");
  }
  const normalized = [];
  const names = new Set();
  let root;
  let extractedBytes = 0;
  for (const entry of entries) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      typeof entry.name !== "string" ||
      !Buffer.isBuffer(entry.content) ||
      !REGULAR_MODES.has(entry.mode)
    ) {
      fail("release archive entry is invalid");
    }
    const entryRoot = validateArchivePath(entry.name);
    if (root === undefined) root = entryRoot;
    if (root !== entryRoot) fail("release archive must contain one root directory");
    if (names.has(entry.name)) {
      fail(`unsafe or duplicate archive path: ${entry.name}`);
    }
    names.add(entry.name);
    if (entry.content.byteLength > MAX_ENTRY_BYTES) {
      fail(`release archive entry exceeds the size limit: ${entry.name}`);
    }
    extractedBytes += entry.content.byteLength;
    if (!Number.isSafeInteger(extractedBytes) || extractedBytes > MAX_EXTRACTED_BYTES) {
      fail("release archive expands beyond the total size limit");
    }
    normalized.push({ content: entry.content, mode: entry.mode, name: entry.name });
  }
  normalized.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
  return normalized;
}

function validateRegularHeader(header) {
  if (
    header === null ||
    typeof header !== "object" ||
    header.type !== "file" ||
    header.linkname !== null ||
    header.pax !== null ||
    header.devmajor !== 0 ||
    header.devminor !== 0 ||
    !Number.isSafeInteger(header.size) ||
    header.size < 0 ||
    header.size > MAX_ENTRY_BYTES
  ) {
    fail(`release archive contains a non-regular or extended entry: ${header?.name ?? "unknown"}`);
  }
  if (
    !REGULAR_MODES.has(header.mode) ||
    header.uid !== 0 ||
    header.gid !== 0 ||
    header.uname !== "root" ||
    header.gname !== "root" ||
    !(header.mtime instanceof Date) ||
    header.mtime.getTime() !== 0
  ) {
    fail(`release archive entry has non-canonical metadata: ${header.name}`);
  }
}

function rejectHiddenHeaderText(tarBytes, headerOffset) {
  for (const [offset, length] of [
    [0, 100],
    [157, 100],
    [265, 32],
    [297, 32],
    [345, 155],
  ]) {
    const field = tarBytes.subarray(headerOffset + offset, headerOffset + offset + length);
    const end = field.indexOf(0);
    if (end >= 0 && field.subarray(end).some((byte) => byte !== 0)) {
      fail("release archive header contains hidden text after a NUL terminator");
    }
  }
}

function validateArchivePath(name) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.startsWith("/") ||
    name.includes("\\") ||
    name.includes("\u0000") ||
    [...name].some((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code <= 0x1f || code === 0x7f;
    }) ||
    /^[A-Za-z]:/u.test(name)
  ) {
    fail(`unsafe or duplicate archive path: ${name}`);
  }
  const parts = name.split("/");
  if (
    parts.length < 2 ||
    parts.some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`unsafe or duplicate archive path: ${name}`);
  }
  if (Buffer.byteLength(name, "utf8") !== name.length || !fitsUstarPath(parts)) {
    fail(`release archive path requires unsupported extended headers: ${name}`);
  }
  return parts[0];
}

function fitsUstarPath(parts) {
  const name = parts.join("/");
  if (name.length <= 100) return true;
  for (let index = 1; index < parts.length; index += 1) {
    const prefix = parts.slice(0, index).join("/");
    const suffix = parts.slice(index).join("/");
    if (prefix.length <= 155 && suffix.length <= 100) return true;
  }
  return false;
}

async function packEntries(entries) {
  const pack = tar.pack();
  try {
    for (const entry of entries) {
      pack.entry(
        {
          gid: 0,
          gname: "root",
          mode: entry.mode,
          mtime: FIXED_MTIME,
          name: entry.name,
          type: "file",
          uid: 0,
          uname: "root",
        },
        entry.content,
      );
    }
    pack.finalize();
    const result = await buffer(pack);
    if (result.byteLength > MAX_TAR_BYTES) fail("tar stream exceeded the size limit");
    return result;
  } catch (error) {
    pack.destroy(error);
    if (isReleaseArchiveError(error)) throw error;
    fail("could not create the deterministic tar stream");
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isReleaseArchiveError(error) {
  return error instanceof Error && error.message.startsWith("release_archive_failed:");
}

function fail(message) {
  throw new Error(`release_archive_failed:${message}`);
}
