import assert from "node:assert/strict";
import test from "node:test";

import {
  REQUESTER_HEADER_NAMES,
} from "@onenod/protocol";
import REQUESTER_SIGNING_TEST_VECTOR from "../../../packages/protocol/test/requester-signing-vector.json" with {
  type: "json",
};

import {
  RequesterAuthenticationError,
  authenticateRequester,
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
