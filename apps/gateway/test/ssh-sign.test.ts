import assert from "node:assert/strict";
import test from "node:test";

import { encodeBase64Url } from "@onenod/protocol";

import {
  describeSshSign,
  parseSshSignRequest,
  sshAuthorizationProofMaterial,
  sshSignExecutorBody,
} from "../src/worker/ssh-sign.js";

const CLIENT = {
  application: "Codex",
  source: "process-ancestry",
};
const FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const METADATA = {
  category: "SshKey",
  fields: [],
  item_id: "item-1",
  ssh: {
    algorithm: "ssh-ed25519",
    fingerprint: FINGERPRINT,
    public_key: "ssh-ed25519 AAAA dummy",
    public_key_blob: "AAAA",
  },
  title: "GitHub SSH Key",
  updated_at: "2026-07-18T00:00:00.000Z",
  version: 3,
};

function ownedBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}

function requestWith(operation: Record<string, unknown>) {
  return parseSshSignRequest({
    action: "ssh.sign",
    algorithm: "ssh-ed25519",
    client: CLIENT,
    data: encodeBase64Url(new TextEncoder().encode("dummy-signing-payload")),
    expected_fingerprint: FINGERPRINT,
    expected_version: 3,
    idempotency_key: "request-1",
    item_id: "item-1",
    operation,
  });
}

test("parses a closed opaque SSH request and keeps bytes out of its description", () => {
  const request = requestWith({ kind: "ssh.opaque-signature" });
  const description = describeSshSign(request, METADATA, "keyed-payload-digest");
  assert.equal(JSON.stringify(description).includes(request.data), false);
  assert.equal(JSON.stringify(description).includes("dummy-signing-payload"), false);
  assert.deepEqual(sshSignExecutorBody(request), {
    algorithm: "ssh-ed25519",
    data: request.data,
    expected_fingerprint: FINGERPRINT,
    expected_version: 3,
    item_id: "item-1",
  });
});

test("describes verified native SSH authentication facts", () => {
  const request = requestWith({
    authentication_method: "publickey-hostbound-v00@openssh.com",
    kind: "ssh.authentication",
    remote_username: "root",
    server_host_key_fingerprint:
      "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    service: "ssh-connection",
    session_binding: "verified",
    session_id_fingerprint:
      "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
  });
  const description = describeSshSign(request, METADATA, "digest");
  assert.ok(description.summary.some(
    (fact) => fact.label === "Remote username" && fact.value === "root",
  ));
  assert.ok(description.summary.some(
    (fact) => fact.label === "Session-bound server host key",
  ));
});

test("allows native SSH when the client cannot verify the server identity", () => {
  const request = requestWith({
    authentication_method: "publickey",
    kind: "ssh.authentication",
    remote_username: "git",
    service: "ssh-connection",
    session_binding: "unavailable",
    session_id_fingerprint:
      "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
  });
  const description = describeSshSign(request, METADATA, "digest");
  assert.ok(description.summary.some(
    (fact) => fact.label === "SSH session (server identity unavailable)",
  ));
});

test("recognizes Git SSHSIG without adapter-supplied repository metadata", () => {
  const request = requestWith({
    kind: "git.ssh-signature",
    namespace: "git",
  });
  const description = describeSshSign(request, METADATA, "digest");
  assert.ok(description.summary.some(
    (fact) => fact.label === "SSH signature namespace" && fact.value === "git",
  ));
  assert.equal(JSON.stringify(description).includes("repository"), false);
});

test("rejects legacy intent, legacy agent context, unknown fields, and algorithm confusion", () => {
  const base = {
    action: "ssh.sign",
    algorithm: "ssh-ed25519",
    client: CLIENT,
    data: encodeBase64Url(new Uint8Array([1, 2, 3])),
    expected_fingerprint: FINGERPRINT,
    expected_version: 3,
    idempotency_key: "request-1",
    item_id: "item-1",
    operation: { kind: "ssh.opaque-signature" },
  };
  assert.throws(() => parseSshSignRequest({ ...base, intent: {} }));
  assert.throws(() => parseSshSignRequest({ ...base, agent_context: {} }));
  assert.throws(() => parseSshSignRequest({ ...base, unexpected: true }));
  assert.throws(() => parseSshSignRequest({ ...base, algorithm: "ecdsa-sha2-nistp256" }));
  assert.throws(() => parseSshSignRequest({ ...base, data: "not+base64url" }));
});

test("SSH authorization proof binds the exact Agent instance, scope, and request", async () => {
  const key = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", key.publicKey),
  );
  const base = {
    action: "ssh.sign",
    algorithm: "ssh-ed25519",
    authorization_session: {
      agent_instance_public_key: encodeBase64Url(publicKey),
      proof: encodeBase64Url(new Uint8Array(64)),
      scope_id: encodeBase64Url(new Uint8Array(32).fill(7)),
      scope_kind: "terminal-session",
    },
    client: CLIENT,
    data: encodeBase64Url(new TextEncoder().encode("dummy-signing-payload")),
    expected_fingerprint: FINGERPRINT,
    expected_version: 3,
    idempotency_key: "request-authorization-1",
    item_id: "item-1",
    operation: { kind: "ssh.opaque-signature" },
  };
  const unsigned = parseSshSignRequest(base);
  const material = sshAuthorizationProofMaterial(unsigned);
  assert.equal(new TextDecoder().decode(material).includes('"proof"'), false);
  const proof = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key.privateKey, ownedBytes(material)),
  );
  const signed = parseSshSignRequest({
    ...base,
    authorization_session: {
      ...base.authorization_session,
      proof: encodeBase64Url(proof),
    },
  });
  assert.equal(
    await crypto.subtle.verify(
      "Ed25519",
      key.publicKey,
      proof,
      ownedBytes(sshAuthorizationProofMaterial(signed)),
    ),
    true,
  );
  signed.authorization_session!.scope_id =
    encodeBase64Url(new Uint8Array(32).fill(8));
  assert.equal(
    await crypto.subtle.verify(
      "Ed25519",
      key.publicKey,
      proof,
      ownedBytes(sshAuthorizationProofMaterial(signed)),
    ),
    false,
  );
});

test("SSH authorization session parser fails closed on malformed capability fields", () => {
  const base = {
    action: "ssh.sign",
    algorithm: "ssh-ed25519",
    authorization_session: {
      agent_instance_public_key: encodeBase64Url(new Uint8Array(32)),
      proof: encodeBase64Url(new Uint8Array(64)),
      scope_id: encodeBase64Url(new Uint8Array(32)),
      scope_kind: "application",
    },
    client: CLIENT,
    data: encodeBase64Url(new Uint8Array([1, 2, 3])),
    expected_fingerprint: FINGERPRINT,
    expected_version: 3,
    idempotency_key: "request-1",
    item_id: "item-1",
    operation: { kind: "ssh.opaque-signature" },
  };
  assert.doesNotThrow(() => parseSshSignRequest(base));
  assert.throws(() =>
    parseSshSignRequest({
      ...base,
      authorization_session: {
        ...base.authorization_session,
        proof: encodeBase64Url(new Uint8Array(63)),
      },
    }),
  );
  assert.throws(() =>
    parseSshSignRequest({
      ...base,
      authorization_session: {
        ...base.authorization_session,
        scope_kind: "all-applications",
      },
    }),
  );
  assert.throws(() =>
    parseSshSignRequest({
      ...base,
      authorization_session: {
        ...base.authorization_session,
        unexpected: true,
      },
    }),
  );
});
