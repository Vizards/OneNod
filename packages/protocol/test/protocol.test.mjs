import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import test from "node:test";

import {
  APPLICATION_ATTESTATION_PROTOCOL,
  buildRequesterCanonicalString,
  canonicalizeJson,
  decodeBase64Url,
  encodeBase64Url,
  formatRequesterCanonicalString,
  formatApplicationAttestationString,
  parseOneNodProductVersion,
  requesterPublicKeyFingerprint,
  sha256Base64Url,
} from "../dist/index.js";
import REQUESTER_SIGNING_TEST_VECTOR from "./requester-signing-vector.json" with {
  type: "json",
};

test("canonicalizes primitives, arrays, and recursively sorted plain objects", () => {
  assert.equal(
    canonicalizeJson({
      zebra: [{ z: null, a: false }, -0],
      alpha: "line\n雪",
    }),
    '{"alpha":"line\\n雪","zebra":[{"a":false,"z":null},0]}',
  );

  const nullPrototype = Object.create(null);
  nullPrototype.b = 2;
  nullPrototype.a = 1;
  assert.equal(canonicalizeJson(nullPrototype), '{"a":1,"b":2}');
});

test("rejects values outside the supported canonical JSON domain", () => {
  const sparseArray = [];
  sparseArray.length = 2;
  sparseArray[1] = 1;

  for (const value of [
    undefined,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    Number.MIN_SAFE_INTEGER - 1,
    1n,
    Symbol("not-json"),
    () => undefined,
    new Date(),
    sparseArray,
    { value: undefined },
    "\ud800",
  ]) {
    assert.throws(() => canonicalizeJson(value), TypeError);
  }

  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalizeJson(cyclic), TypeError);
  assert.equal(canonicalizeJson(Number.MAX_SAFE_INTEGER), "9007199254740991");
  assert.equal(canonicalizeJson(Number.MIN_SAFE_INTEGER), "-9007199254740991");
});

test("base64url round-trips bytes and rejects padded or non-canonical input", () => {
  const bytes = Uint8Array.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const encoded = encodeBase64Url(bytes);

  assert.equal(encoded, "AAEC-vv8_f7_");
  assert.deepEqual(decodeBase64Url(encoded), bytes);
  assert.equal(encodeBase64Url(new TextEncoder().encode("hello")), "aGVsbG8");
  assert.throws(() => decodeBase64Url("aGVsbG8="), TypeError);
  assert.throws(() => decodeBase64Url("A"), TypeError);
  assert.throws(() => decodeBase64Url("AB"), TypeError);
});

test("parses only stable, alpha.N, and beta.N OneNod product versions", () => {
  assert.deepEqual(parseOneNodProductVersion("1.2.3"), {
    channel: "stable",
    version: "1.2.3",
  });
  assert.deepEqual(parseOneNodProductVersion("1.2.3-alpha.1"), {
    channel: "alpha",
    version: "1.2.3-alpha.1",
  });
  assert.deepEqual(parseOneNodProductVersion("1.2.3-beta.12"), {
    channel: "beta",
    version: "1.2.3-beta.12",
  });
  for (const value of [
    "1.2.3-alpha.0",
    "1.2.3-beta.01",
    "1.2.3-rc.1",
    "1.2.3+build",
    "01.2.3",
    "9007199254740992.0.0",
    null,
  ]) {
    assert.equal(parseOneNodProductVersion(value), null);
  }
});

test("matches the fixed canonical JSON and requester signing vector", async () => {
  const material = await buildRequesterCanonicalString(REQUESTER_SIGNING_TEST_VECTOR.input);

  assert.deepEqual(material, {
    body_canonical_json: REQUESTER_SIGNING_TEST_VECTOR.expected.body_canonical_json,
    body_sha256: REQUESTER_SIGNING_TEST_VECTOR.expected.body_sha256,
    canonical_string: REQUESTER_SIGNING_TEST_VECTOR.expected.canonical_string,
  });
  assert.equal(
    await sha256Base64Url(material.canonical_string),
    REQUESTER_SIGNING_TEST_VECTOR.expected.canonical_string_sha256,
  );
  assert.equal(
    await requesterPublicKeyFingerprint(
      REQUESTER_SIGNING_TEST_VECTOR.expected.ed25519_public_key,
    ),
    REQUESTER_SIGNING_TEST_VECTOR.expected.ed25519_public_key_sha256,
  );

  const spkiPrefix = Uint8Array.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const pkcs8Prefix = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
    0x22, 0x04, 0x20,
  ]);
  const privateKey = createPrivateKey({
    format: "der",
    key: Buffer.concat([
      pkcs8Prefix,
      decodeBase64Url(REQUESTER_SIGNING_TEST_VECTOR.test_only_ed25519_seed),
    ]),
    type: "pkcs8",
  });
  const publicKey = createPublicKey({
    format: "der",
    key: Buffer.concat([
      spkiPrefix,
      decodeBase64Url(REQUESTER_SIGNING_TEST_VECTOR.expected.ed25519_public_key),
    ]),
    type: "spki",
  });
  const signature = decodeBase64Url(
    REQUESTER_SIGNING_TEST_VECTOR.expected.ed25519_signature,
  );

  assert.equal(
    encodeBase64Url(sign(null, Buffer.from(material.canonical_string), privateKey)),
    REQUESTER_SIGNING_TEST_VECTOR.expected.ed25519_signature,
  );
  assert.equal(
    verify(
      null,
      Buffer.from(material.canonical_string),
      publicKey,
      signature,
    ),
    true,
  );
});

test("rejects ambiguous requester canonical-string fields", () => {
  const validFields = {
    audience: "example.workers.dev",
    body_sha256: "digest",
    device_id: "device",
    method: "POST",
    nonce: "nonce",
    path: "/v1/requests",
    unix_seconds: 1,
  };

  assert.throws(
    () => formatRequesterCanonicalString({ ...validFields, method: "post" }),
    TypeError,
  );
  assert.throws(
    () => formatRequesterCanonicalString({ ...validFields, path: "/v1/requests?q=x" }),
    TypeError,
  );
  assert.throws(
    () => formatRequesterCanonicalString({ ...validFields, nonce: "bad\nnonce" }),
    TypeError,
  );
  assert.throws(
    () => formatRequesterCanonicalString({ ...validFields, unix_seconds: -1 }),
    TypeError,
  );
});

test("formats an application attestation around the complete requester signature material", () => {
  const requesterCanonical = [
    "onenod-request-v1",
    "example.workers.dev",
    "POST",
    "/v1/requests",
    "body-digest",
    "requester-device",
    "42",
    "nonce",
  ].join("\n");
  assert.equal(
    formatApplicationAttestationString({
      principal_id: "principal",
      principal_scheme: "macos-designated-requirement-v1",
      requester_canonical_string: requesterCanonical,
    }),
    [
      APPLICATION_ATTESTATION_PROTOCOL,
      requesterCanonical,
      "macos-designated-requirement-v1",
      "principal",
    ].join("\n"),
  );
  assert.throws(
    () => formatApplicationAttestationString({
      principal_id: "principal\nforged",
      principal_scheme: "macos-designated-requirement-v1",
      requester_canonical_string: requesterCanonical,
    }),
    TypeError,
  );
});
