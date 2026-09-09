import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalizeJson,
  decodeBase64Url,
  encodeBase64Url,
  type BeholderAuthorizationRequest,
} from "@onenod/protocol";

import {
  beholderAuthorizationMaterial,
  evaluateBeholderAuthorization,
  separateBeholderAuthorization,
} from "../src/worker/beholder-authorization.js";
import { claimBeholderAuthorization } from "../src/worker/approval-request-repository.js";
import { parseSshSignRequest, sshAuthorizationProofMaterial } from "../src/worker/ssh-sign.js";
import { approvalStorage } from "./support/sqlite-do-storage.js";

const REQUESTER = "0199ad30-f672-7449-933e-968aa84f0342";
const NOW = 1_800_000_000;

async function fixture(body?: Record<string, unknown>) {
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const publicKeyText = encodeBase64Url(publicKey);
  const keyId = encodeBase64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey)),
  );
  const semanticBody = body ?? {
    action: "secret.read",
    client: { application: "Codex", source: "unavailable" },
    expected_version: 7,
    field_id: "credential",
    idempotency_key: "0199ad30-f672-7449-933e-968aa84f0343",
    item_id: "fixture-a",
  };
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonicalizeJson(semanticBody)),
    ),
  );
  const unsigned: Omit<BeholderAuthorizationRequest, "signature"> = {
    schema_version: 1,
    decision: "allow",
    evidence_id: "shadow-00112233445566778899aabbccddeeff",
    expires_at: NOW + 20,
    issued_at: NOW,
    key_id: keyId,
    operation_target_sha256: Array.from(
      digest,
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join(""),
    requester_device_id: REQUESTER,
  };
  const signature = encodeBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        keys.privateKey,
        new TextEncoder().encode(beholderAuthorizationMaterial(unsigned)),
      ),
    ),
  );
  return {
    authorization: { ...unsigned, signature },
    authorityKeysJson: JSON.stringify([
      { public_key: publicKeyText, requester_device_id: REQUESTER },
    ]),
    semanticBody,
  };
}

test("valid Core signature authorizes only its exact canonical request", async () => {
  const value = await fixture();
  const accepted = await evaluateBeholderAuthorization({
    ...value,
    authorityMode: "dogfood-v1",
    nowSeconds: NOW + 1,
    requesterDeviceId: REQUESTER,
  });
  assert.equal(accepted.required, true);
  assert.deepEqual(accepted.accepted, {
    evidenceId: value.authorization.evidence_id,
    keyId: value.authorization.key_id,
    operationTargetSha256: value.authorization.operation_target_sha256,
  });

  const changed = await evaluateBeholderAuthorization({
    ...value,
    authorityMode: "dogfood-v1",
    nowSeconds: NOW + 1,
    requesterDeviceId: REQUESTER,
    semanticBody: { ...value.semanticBody, item_id: "fixture-b" },
  });
  assert.equal(changed.required, true);
  assert.equal(changed.accepted, undefined);
});

test("accepts the fixed Core and Gateway Ed25519 interoperability vector", async () => {
  const semanticBody = {
    action: "secret.read",
    client: { application: "Codex", source: "unavailable" },
    expected_version: 7,
    field_id: "credential",
    idempotency_key: "0199ad30-f672-7449-933e-968aa84f0343",
    item_id: "fixture-a",
  };
  const authorization: BeholderAuthorizationRequest = {
    schema_version: 1,
    decision: "allow",
    evidence_id: "shadow-vector-00112233445566778899",
    expires_at: NOW + 30,
    issued_at: NOW,
    key_id: "Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
    operation_target_sha256:
      "08b31c4def69da6356b06665207399b4540d06797b70ceb47467ab5cc155ac62",
    requester_device_id: REQUESTER,
    signature:
      "yKeTMU2ZEkc9W2E-PSaevQBpTtYnst5BUxgzECrAekLJrNzgZlY7T7zCmcwYZX0dLvqEfXzYJgDp7VfPy8sHCQ",
  };
  const evaluated = await evaluateBeholderAuthorization({
    authorization,
    authorityKeysJson: JSON.stringify([{
      public_key: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
      requester_device_id: REQUESTER,
    }]),
    authorityMode: "dogfood-v1",
    nowSeconds: NOW + 1,
    requesterDeviceId: REQUESTER,
    semanticBody,
  });
  assert.equal(evaluated.accepted?.evidenceId, authorization.evidence_id);
});

test("expiry, requester mismatch, and invalid deployment config fail to human approval", async () => {
  const value = await fixture();
  for (const input of [
    { nowSeconds: NOW + 20, requesterDeviceId: REQUESTER },
    { nowSeconds: NOW + 1, requesterDeviceId: "another-requester" },
  ]) {
    const evaluated = await evaluateBeholderAuthorization({
      ...value,
      ...input,
      authorityMode: "dogfood-v1",
    });
    assert.equal(evaluated.accepted, undefined);
    assert.equal(evaluated.required, input.requesterDeviceId === REQUESTER);
  }

  const malformed = await evaluateBeholderAuthorization({
    ...value,
    authorityKeysJson: "not-json",
    authorityMode: "dogfood-v1",
    nowSeconds: NOW + 1,
    requesterDeviceId: "otherwise-unlisted-requester",
  });
  assert.deepEqual(malformed, { required: true });
});

test("human-only kill switch ignores Beholder evidence", async () => {
  const value = await fixture();
  assert.deepEqual(
    await evaluateBeholderAuthorization({
      ...value,
      authorityMode: "human-only",
      nowSeconds: NOW + 1,
      requesterDeviceId: REQUESTER,
    }),
    { required: false },
  );
});

test("authorization envelope is excluded from the semantic body", async () => {
  const value = await fixture();
  const split = separateBeholderAuthorization({
    ...value.semanticBody,
    beholder_authorization: value.authorization,
  });
  assert.deepEqual(split.semanticBody, value.semanticBody);
  assert.deepEqual(split.authorization, value.authorization);
});

test("Core authorization preserves the SSH application proof through admission parsing", async () => {
  const sessionKey = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", sessionKey.publicKey));
  const body = {
    action: "ssh.sign",
    algorithm: "ssh-ed25519",
    authorization_session: {
      agent_instance_public_key: encodeBase64Url(publicKey),
      proof: encodeBase64Url(new Uint8Array(64)),
      scope_id: encodeBase64Url(new Uint8Array(32).fill(7)),
      scope_kind: "application",
    },
    client: { application: "Codex", source: "process-ancestry" },
    data: encodeBase64Url(new TextEncoder().encode("dummy-signing-payload")),
    expected_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    expected_version: 3,
    idempotency_key: "request-beholder-session-1",
    item_id: "item-1",
    operation: { kind: "ssh.opaque-signature" },
  };
  body.authorization_session.proof = encodeBase64Url(new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519", sessionKey.privateKey,
      new Uint8Array(sshAuthorizationProofMaterial(parseSshSignRequest(body))),
    ),
  ));
  const value = await fixture(body);
  const split = separateBeholderAuthorization({
    ...body, beholder_authorization: value.authorization,
  });
  const accepted = await evaluateBeholderAuthorization({
    ...value,
    authorization: split.authorization,
    semanticBody: split.semanticBody,
    authorityMode: "dogfood-v1",
    nowSeconds: NOW + 1,
    requesterDeviceId: REQUESTER,
  });
  assert.equal(accepted.accepted?.evidenceId, value.authorization.evidence_id);
  const parsed = parseSshSignRequest(split.semanticBody);
  const verify = () => crypto.subtle.verify(
    "Ed25519", sessionKey.publicKey,
    new Uint8Array(decodeBase64Url(parsed.authorization_session!.proof)),
    new Uint8Array(sshAuthorizationProofMaterial(parsed)),
  );
  assert.equal(await verify(), true);
  parsed.item_id = "changed-item";
  assert.equal(await verify(), false);
  const changed = await evaluateBeholderAuthorization({
    ...value,
    semanticBody: { ...split.semanticBody, item_id: "changed-item" },
    authorityMode: "dogfood-v1",
    nowSeconds: NOW + 1,
    requesterDeviceId: REQUESTER,
  });
  assert.equal(changed.accepted, undefined);
});

test("an accepted evidence identity can authorize only one Gateway request", () => {
  const { database, sql } = approvalStorage();
  const authorization = {
    evidenceId: "shadow-single-use-00112233445566778899",
    keyId: "key-id",
    operationTargetSha256: "a".repeat(64),
  };
  assert.equal(
    claimBeholderAuthorization(
      sql,
      "request-first",
      REQUESTER,
      authorization,
      NOW * 1_000,
    ),
    true,
  );
  assert.equal(
    claimBeholderAuthorization(
      sql,
      "request-replay",
      REQUESTER,
      authorization,
      NOW * 1_000 + 1,
    ),
    false,
  );
  assert.deepEqual(
    database.prepare(
      `SELECT evidence_id, requester_device_id, request_id
       FROM beholder_authorization_uses`,
    ).all().map((row) => ({ ...row })),
    [{
      evidence_id: authorization.evidenceId,
      requester_device_id: REQUESTER,
      request_id: "request-first",
    }],
  );
});
