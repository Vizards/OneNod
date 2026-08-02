import assert from "node:assert/strict";
import test from "node:test";

import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";

import {
  SshSignerError,
  projectWireSshKeyMetadata,
  signWireSshData,
  type SshSignatureAlgorithm,
} from "../src/ssh-signer.ts";
import type { WireItem } from "../src/onepassword-wire.ts";

const { utils } = ssh2;
const MESSAGE = new TextEncoder().encode("dummy OpenSSH authentication payload");
const RAW_FIELD_SECRET = "raw-wire-item-value-must-never-be-used";

const candidates = [
  {
    algorithm: "ssh-ed25519",
    generate: generateTestEd25519KeyPair,
  },
  {
    algorithm: "rsa-sha2-256",
    generate: () => utils.generateKeyPairSync("rsa", { bits: 2_048 }),
  },
  {
    algorithm: "rsa-sha2-512",
    generate: () => utils.generateKeyPairSync("rsa", { bits: 2_048 }),
  },
] as const;

for (const candidate of candidates) {
  test(`signs and independently verifies ${candidate.algorithm}`, () => {
    const keys = candidate.generate();
    const item = sshItem(keys.public);
    const metadata = projectWireSshKeyMetadata(item);
    assert.ok(metadata);

    const result = signWireSshData({
      data: MESSAGE,
      expectedFingerprint: metadata.fingerprint,
      expectedVersion: item.version,
      item,
      privateKey: keys.private,
      requestedAlgorithm: candidate.algorithm,
    });

    assert.equal(result.signature_algorithm, candidate.algorithm);
    assert.equal(result.item_id, item.id);
    assert.equal(result.version, item.version);
    assert.equal(result.public_key_blob, metadata.public_key_blob);
    assertReturnedSignatureVerifies(
      keys.public,
      candidate.algorithm,
      MESSAGE,
      Buffer.from(result.signature_blob, "base64url"),
    );
    assert.equal(JSON.stringify(result).includes(keys.private), false);
    assert.equal(JSON.stringify(result).includes(RAW_FIELD_SECRET), false);
  });
}

test("projects only public SSH metadata and identifies the resolver field", () => {
  const keys = generateTestEd25519KeyPair();
  const item = sshItem(keys.public);
  const metadata = projectWireSshKeyMetadata(item);

  assert.ok(metadata);
  assert.equal(metadata.algorithm, "ssh-ed25519");
  assert.equal(metadata.field_id, "private_key");
  assert.match(metadata.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/u);
  assert.equal(metadata.public_key, keys.public.trim());
  assert.equal(JSON.stringify(metadata).includes(RAW_FIELD_SECRET), false);
  assert.equal(projectWireSshKeyMetadata({ ...item, category: "Login" }), undefined);
});

test("rejects ECDSA SSH keys that 1Password item creation cannot support", () => {
  const keys = utils.generateKeyPairSync("ecdsa", { bits: 256 });
  assertSshError(
    () => projectWireSshKeyMetadata(sshItem(keys.public)),
    "ssh_algorithm_unsupported",
  );
});

test("rejects stale metadata before parsing private key material", () => {
  const keys = generateTestEd25519KeyPair();
  const item = sshItem(keys.public);
  const metadata = projectWireSshKeyMetadata(item);
  assert.ok(metadata);

  assertSshError(
    () =>
      signWireSshData({
        data: MESSAGE,
        expectedFingerprint: metadata.fingerprint,
        expectedVersion: item.version - 1,
        item,
        privateKey: "private-key-canary-that-must-not-be-parsed-or-returned",
        requestedAlgorithm: "ssh-ed25519",
      }),
    "item_stale",
  );
});

test("rejects fingerprint, key, and signature-algorithm confusion", () => {
  const keys = generateTestEd25519KeyPair();
  const otherKeys = generateTestEd25519KeyPair();
  const item = sshItem(keys.public);
  const metadata = projectWireSshKeyMetadata(item);
  assert.ok(metadata);

  assertSshError(
    () =>
      signWireSshData({
        data: MESSAGE,
        expectedFingerprint:
          "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        expectedVersion: item.version,
        item,
        privateKey: keys.private,
        requestedAlgorithm: "ssh-ed25519",
      }),
    "ssh_key_mismatch",
  );
  assertSshError(
    () =>
      signWireSshData({
        data: MESSAGE,
        expectedFingerprint: metadata.fingerprint,
        expectedVersion: item.version,
        item,
        privateKey: otherKeys.private,
        requestedAlgorithm: "ssh-ed25519",
      }),
    "ssh_key_mismatch",
  );
  assertSshError(
    () =>
      signWireSshData({
        data: MESSAGE,
        expectedFingerprint: metadata.fingerprint,
        expectedVersion: item.version,
        item,
        privateKey: keys.private,
        requestedAlgorithm: "rsa-sha2-512",
      }),
    "ssh_algorithm_mismatch",
  );
});

test("accepts only a single SSH field and an unencrypted OpenSSH private key", () => {
  const keys = generateTestEd25519KeyPair();
  const item = sshItem(keys.public);
  const metadata = projectWireSshKeyMetadata(item);
  assert.ok(metadata);

  assertSshError(
    () =>
      projectWireSshKeyMetadata({
        ...item,
        fields: [...item.fields, structuredClone(item.fields[0]!)],
      }),
    "ssh_key_invalid",
  );
  const pem = parseSingleTestKey(keys.private).getPrivatePEM();
  assertSshError(
    () =>
      signWireSshData({
        data: MESSAGE,
        expectedFingerprint: metadata.fingerprint,
        expectedVersion: item.version,
        item,
        privateKey: pem,
        requestedAlgorithm: "ssh-ed25519",
      }),
    "ssh_key_invalid",
  );
});

test("private-key parse failures expose only a stable safe code", () => {
  const keys = generateTestEd25519KeyPair();
  const item = sshItem(keys.public);
  const metadata = projectWireSshKeyMetadata(item);
  assert.ok(metadata);
  const secretCanary = `${"-----BEGIN OPENSSH " + "PRIVATE KEY-----"}\nsecret-shaped-canary\n${"-----END OPENSSH " + "PRIVATE KEY-----"}`;

  assert.throws(
    () =>
      signWireSshData({
        data: MESSAGE,
        expectedFingerprint: metadata.fingerprint,
        expectedVersion: item.version,
        item,
        privateKey: secretCanary,
        requestedAlgorithm: "ssh-ed25519",
      }),
    (error: unknown) => {
      assert.ok(error instanceof SshSignerError);
      assert.equal(error.code, "ssh_key_invalid");
      assert.equal(error.message, "ssh_key_invalid");
      assert.equal(JSON.stringify(error).includes("secret-shaped-canary"), false);
      return true;
    },
  );
});

function sshItem(publicKey: string): WireItem {
  return {
    category: "SshKey",
    createdAt: "2026-07-18T00:00:00.000Z",
    fields: [
      {
        details: {
          content: {
            fingerprint: "ignored-in-favor-of-computed-fingerprint",
            keyType: "test",
            publicKey,
          },
          type: "SshKey",
        },
        fieldType: "SshKey",
        id: "private_key",
        title: "private key",
        value: RAW_FIELD_SECRET,
      },
    ],
    files: [],
    id: "sshitem00000000000000001",
    notes: "",
    sections: [],
    tags: [],
    title: "Disposable SSH key",
    updatedAt: "2026-07-18T00:00:00.000Z",
    vaultId: "vault0000000000000000001",
    version: 3,
    websites: [],
  };
}

function generateTestEd25519KeyPair(): ReturnType<
  typeof utils.generateKeyPairSync
> {
  // ssh2 1.17.0 can omit a leading zero byte from roughly one in 256
  // generated Ed25519 public blobs. Production correctly rejects that
  // malformed 31-byte key; tests retry until the upstream fixture is valid.
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const keys = utils.generateKeyPairSync("ed25519");
    const parsed = utils.parseKey(keys.public);
    if (!(parsed instanceof Error) && !Array.isArray(parsed)) return keys;
  }
  throw new Error("ssh2_failed_to_generate_a_valid_ed25519_test_fixture");
}

function assertSshError(
  invoke: () => unknown,
  code: SshSignerError["code"],
): void {
  assert.throws(
    invoke,
    (error: unknown) =>
      error instanceof SshSignerError &&
      error.code === code &&
      error.message === code,
  );
}

function assertReturnedSignatureVerifies(
  publicKey: string,
  algorithm: SshSignatureAlgorithm,
  data: Uint8Array,
  signatureBlob: Buffer,
): void {
  const parsed = parseSingleTestKey(publicKey);
  const hashAlgorithm =
    algorithm === "rsa-sha2-256"
      ? "sha256"
      : algorithm === "rsa-sha2-512"
        ? "sha512"
        : undefined;
  assert.equal(parsed.verify(Buffer.from(data), signatureBlob, hashAlgorithm), true);
}

function parseSingleTestKey(value: string): ParsedKey {
  const parsed = utils.parseKey(value);
  if (parsed instanceof Error || Array.isArray(parsed)) throw parsed;
  return parsed;
}
