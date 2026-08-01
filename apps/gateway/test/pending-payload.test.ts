import assert from "node:assert/strict";
import test from "node:test";

import { encodeBase64Url } from "@onenod/protocol";

import {
  decryptPendingPayload,
  encryptPendingPayload,
  type PendingPayloadContext,
} from "../src/worker/pending-payload.js";

const MASTER_KEY = encodeBase64Url(new Uint8Array(32).fill(7));
const CONTEXT: PendingPayloadContext = {
  action: "item.patch",
  environment: "dev",
  expiresAt: 1_800_000_000_000,
  requestId: "request-1",
  requesterDeviceId: "device-1",
};

test("pending payload encryption binds context and keeps values out of metadata", async () => {
  const payload = {
    operations: [{ field_id: "token", op: "replace", value: "dummy-secret" }],
  };
  const encrypted = await encryptPendingPayload(MASTER_KEY, CONTEXT, payload);

  assert.deepEqual(
    await decryptPendingPayload(MASTER_KEY, CONTEXT, encrypted),
    payload,
  );
  assert.equal(JSON.stringify(encrypted).includes("dummy-secret"), false);
  assert.equal(encrypted.digest.length > 32, true);
});

test("pending payload encryption rejects changed context, ciphertext, and digest", async () => {
  const encrypted = await encryptPendingPayload(MASTER_KEY, CONTEXT, {
    value: "dummy-secret",
  });
  await assert.rejects(
    decryptPendingPayload(MASTER_KEY, { ...CONTEXT, requestId: "request-2" }, encrypted),
    /pending_payload_context_mismatch/u,
  );

  const changedCiphertext = `${
    encrypted.ciphertext.startsWith("A") ? "B" : "A"
  }${encrypted.ciphertext.slice(1)}`;
  await assert.rejects(
    decryptPendingPayload(MASTER_KEY, { ...CONTEXT }, {
      ...encrypted,
      ciphertext: changedCiphertext,
    }),
    /pending_payload_decryption_failed/u,
  );

  const changedDigest = `${
    encrypted.digest.startsWith("A") ? "B" : "A"
  }${encrypted.digest.slice(1)}`;
  await assert.rejects(
    decryptPendingPayload(MASTER_KEY, CONTEXT, { ...encrypted, digest: changedDigest }),
    /pending_payload_digest_mismatch/u,
  );
});

test("pending payload encryption requires a canonical 32-byte master key", async () => {
  await assert.rejects(
    encryptPendingPayload("not-base64url!", CONTEXT, { value: "dummy" }),
    /Expected unpadded base64url/u,
  );
  await assert.rejects(
    encryptPendingPayload(encodeBase64Url(new Uint8Array(31)), CONTEXT, { value: "dummy" }),
    /gateway_master_key_invalid/u,
  );
});
