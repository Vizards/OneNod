import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import test from "node:test";

import {
  APPLICATION_ATTESTATION_HEADER,
  REQUESTER_HEADER_NAMES,
  buildRequesterCanonicalString,
  decodeBase64Url,
  encodeBase64Url,
  formatApplicationAttestationString,
  requesterPublicKeyFingerprint,
} from "@onenod/protocol";
import REQUESTER_SIGNING_TEST_VECTOR from "../../../packages/protocol/test/requester-signing-vector.json" with {
  type: "json",
};

import {
  RequesterAuthenticationError,
  authenticateRequester,
  authenticateRequesterSelf,
  verifyApplicationAttestation,
} from "../src/worker/requester-auth.js";

test("authenticates the shared Ed25519 requester test vector once", async () => {
  const vector = REQUESTER_SIGNING_TEST_VECTOR;
  const nonces = new Set<string>();
  const request = new Request("https://example.test/v1/requests", {
    body: JSON.stringify(vector.input.body),
    headers: {
      [REQUESTER_HEADER_NAMES.deviceId]: vector.input.device_id,
      [REQUESTER_HEADER_NAMES.nonce]: vector.input.nonce,
      [REQUESTER_HEADER_NAMES.signature]:
        vector.expected.ed25519_signature,
      [REQUESTER_HEADER_NAMES.timestamp]: String(
        vector.input.unix_seconds,
      ),
      "content-type": "application/json",
    },
    method: "POST",
  });

  const originalNow = Date.now;
  Date.now = () => vector.input.unix_seconds * 1_000;
  try {
    const result = await authenticateRequester({
      audience: vector.input.audience,
      body: vector.input.body,
      lookupRequester: () => ({
        displayName: "test-requester",
        publicKey: vector.expected.ed25519_public_key,
      }),
      method: "POST",
      path: "/v1/requests",
      request,
      useNonce: (_deviceId, nonce) => {
        if (nonces.has(nonce)) return false;
        nonces.add(nonce);
        return true;
      },
    });
    assert.equal(result.displayName, "test-requester");

    await assert.rejects(
      authenticateRequester({
        audience: vector.input.audience,
        body: vector.input.body,
        lookupRequester: () => ({
          displayName: "test-requester",
          publicKey: vector.expected.ed25519_public_key,
        }),
        method: "POST",
        path: "/v1/requests",
        request,
        useNonce: (_deviceId, nonce) => {
          if (nonces.has(nonce)) return false;
          nonces.add(nonce);
          return true;
        },
      }),
      (error: unknown) =>
        error instanceof RequesterAuthenticationError &&
        error.code === "request_replayed",
    );
  } finally {
    Date.now = originalNow;
  }
});

test("runs admission control after signature verification but before nonce storage", async () => {
  const vector = REQUESTER_SIGNING_TEST_VECTOR;
  const request = new Request("https://example.test/v1/requests", {
    body: JSON.stringify(vector.input.body),
    headers: {
      [REQUESTER_HEADER_NAMES.deviceId]: vector.input.device_id,
      [REQUESTER_HEADER_NAMES.nonce]: vector.input.nonce,
      [REQUESTER_HEADER_NAMES.signature]: vector.expected.ed25519_signature,
      [REQUESTER_HEADER_NAMES.timestamp]: String(vector.input.unix_seconds),
      "content-type": "application/json",
    },
    method: "POST",
  });
  const rejected = new Error("rate_limited");
  let nonceWrites = 0;
  const originalNow = Date.now;
  Date.now = () => vector.input.unix_seconds * 1_000;
  try {
    await assert.rejects(
      authenticateRequester({
        audience: vector.input.audience,
        beforeUseNonce(identity) {
          assert.equal(identity.deviceId, vector.input.device_id);
          throw rejected;
        },
        body: vector.input.body,
        lookupRequester: () => ({
          displayName: "test-requester",
          publicKey: vector.expected.ed25519_public_key,
        }),
        method: "POST",
        path: "/v1/requests",
        request,
        useNonce: () => {
          nonceWrites += 1;
          return true;
        },
      }),
      (error: unknown) => error === rejected,
    );
    assert.equal(nonceWrites, 0);
  } finally {
    Date.now = originalNow;
  }
});

test("proves an active requester through a signed read-only self request", async () => {
  const vector = REQUESTER_SIGNING_TEST_VECTOR;
  const timestamp = vector.input.unix_seconds;
  const nonce = "requester-self-proof";
  const material = await buildRequesterCanonicalString({
    audience: vector.input.audience,
    body: {},
    device_id: vector.input.device_id,
    method: "GET",
    nonce,
    path: "/v1/requester-self",
    unix_seconds: timestamp,
  });
  const pkcs8Prefix = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
  ]);
  const privateKey = createPrivateKey({
    format: "der",
    key: Buffer.concat([
      pkcs8Prefix,
      decodeBase64Url(vector.test_only_ed25519_seed),
    ]),
    type: "pkcs8",
  });
  const signature = encodeBase64Url(
    sign(null, Buffer.from(material.canonical_string), privateKey),
  );
  const request = new Request("https://example.test/v1/requester-self", {
    headers: {
      [REQUESTER_HEADER_NAMES.deviceId]: vector.input.device_id,
      [REQUESTER_HEADER_NAMES.nonce]: nonce,
      [REQUESTER_HEADER_NAMES.signature]: signature,
      [REQUESTER_HEADER_NAMES.timestamp]: String(timestamp),
    },
    method: "GET",
  });
  let admitted = 0;
  const originalNow = Date.now;
  Date.now = () => timestamp * 1_000;
  try {
    const response = await authenticateRequesterSelf({
      audience: vector.input.audience,
      beforeUseNonce: () => {
        admitted += 1;
      },
      lookupRequester: () => ({
        displayName: "test-requester",
        publicKey: vector.expected.ed25519_public_key,
      }),
      request,
    });
    assert.deepEqual(response, {
      device_id: vector.input.device_id,
      public_key_fingerprint: await requesterPublicKeyFingerprint(
        vector.expected.ed25519_public_key,
      ),
      registered: true,
    });
    assert.deepEqual(Object.keys(response).sort(), [
      "device_id",
      "public_key_fingerprint",
      "registered",
    ]);
    assert.equal(admitted, 1);

    await assert.rejects(
      authenticateRequesterSelf({
        audience: vector.input.audience,
        lookupRequester: () => undefined,
        request,
      }),
      (error: unknown) =>
        error instanceof RequesterAuthenticationError &&
        error.code === "requester_not_found",
    );
  } finally {
    Date.now = originalNow;
  }
});

test("verifies a helper application attestation bound to the complete requester request", async () => {
  const vector = REQUESTER_SIGNING_TEST_VECTOR;
  const identity = {
    assurance: "verified-code-signature" as const,
    platform: "macos" as const,
    principal_id: encodeBase64Url(new Uint8Array(32).fill(9)),
    principal_scheme: "macos-designated-requirement-v1" as const,
    signer_name: "OpenAI OpCo, LLC",
    signing_identifier: "com.openai.codex",
    team_identifier: "2DC432GLL2",
  };
  const material = formatApplicationAttestationString({
    principal_id: identity.principal_id,
    principal_scheme: identity.principal_scheme,
    requester_canonical_string: vector.expected.canonical_string,
  });
  const pkcs8Prefix = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
  ]);
  const privateKey = createPrivateKey({
    format: "der",
    key: Buffer.concat([
      pkcs8Prefix,
      decodeBase64Url(vector.test_only_ed25519_seed),
    ]),
    type: "pkcs8",
  });
  const signature = encodeBase64Url(sign(null, Buffer.from(material), privateKey));
  const request = new Request("https://example.test/v1/requests", {
    headers: { [APPLICATION_ATTESTATION_HEADER]: signature },
    method: "POST",
  });
  const requester = {
    canonicalString: vector.expected.canonical_string,
    deviceId: vector.input.device_id,
    displayName: "test-requester",
    publicKey: vector.expected.ed25519_public_key,
  };

  assert.equal(
    await verifyApplicationAttestation({ identity, request, requester }),
    true,
  );
  assert.equal(
    await verifyApplicationAttestation({
      identity: {
        ...identity,
        principal_id: encodeBase64Url(new Uint8Array(32).fill(10)),
      },
      request,
      requester,
    }),
    false,
  );
  assert.equal(
    await verifyApplicationAttestation({
      identity,
      request,
      requester: {
        ...requester,
        canonicalString: `${requester.canonicalString}-changed`,
      },
    }),
    false,
  );
  assert.equal(
    await verifyApplicationAttestation({
      identity,
      request: new Request("https://example.test/v1/requests"),
      requester,
    }),
    false,
  );
});
