import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { type DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  APPLICATION_ATTESTATION_HEADER,
  REQUESTER_HEADER_NAMES,
  buildRequesterCanonicalString,
  encodeBase64Url,
  formatApplicationAttestationString,
} from "@onenod/protocol";

import {
  ACTIVE_SECRET_GRANT_CONSUME_PREDICATE,
  ACTIVE_SECRET_GRANT_LOOKUP_PREDICATE,
  ACTIVE_SSH_GRANT_CONSUME_PREDICATE,
  ACTIVE_SSH_GRANT_LOOKUP_PREDICATE,
  REJECT_QUEUED_REQUESTS_FOR_CREDENTIAL_SQL,
  REJECT_QUEUED_REQUESTS_FOR_REQUESTER_SQL,
  rememberedAuthorizationDurationAvailable,
  incrementRememberedGrantUse,
  rejectQueuedRequestsForGrantSql,
} from "../src/worker/authorization-grants.js";
import {
  authenticateRequester,
  verifyApplicationAttestation,
} from "../src/worker/requester-auth.js";
import {
  insertRequest as insertProductionRequest,
  type RequestInsertSql,
} from "../src/worker/approval-request-repository.js";
import { approvalStorage } from "./support/sqlite-do-storage.js";

const NOW = 1_800_000_000_000;
const REQUESTER_ID = "requester-a";
const APPLICATION_ID = encodeBase64Url(new Uint8Array(32).fill(9));

interface TestApplication {
  assurance: "unverified" | "verified-code-signature";
  principalId: string | null;
  principalScheme: string | null;
  signingIdentifier: string | null;
}

async function authenticateApplication(
  includeAttestation: boolean,
): Promise<TestApplication> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  if (typeof publicJwk.x !== "string") throw new Error("missing_public_key");
  const requesterPublicKey = publicJwk.x;
  const timestamp = Math.floor(NOW / 1_000);
  const body = {
    action: "secret.read",
    authorization_scope: {
      principal_id: APPLICATION_ID,
      principal_scheme: "macos-designated-requirement-v1",
      scope_id: APPLICATION_ID,
    },
    item_id: "item-a",
  };
  const material = await buildRequesterCanonicalString({
    audience: "https://gateway.test",
    body,
    device_id: REQUESTER_ID,
    method: "POST",
    nonce: "nonce-a",
    path: "/v1/requests",
    unix_seconds: timestamp,
  });
  const identity = {
    assurance: "verified-code-signature" as const,
    platform: "macos" as const,
    principal_id: APPLICATION_ID,
    principal_scheme: "macos-designated-requirement-v1" as const,
    signer_name: "OpenAI OpCo, LLC",
    signing_identifier: "com.openai.codex",
    team_identifier: "2DC432GLL2",
  };
  const headers = new Headers({
    [REQUESTER_HEADER_NAMES.deviceId]: REQUESTER_ID,
    [REQUESTER_HEADER_NAMES.nonce]: "nonce-a",
    [REQUESTER_HEADER_NAMES.signature]: encodeBase64Url(
      sign(null, Buffer.from(material.canonical_string), privateKey),
    ),
    [REQUESTER_HEADER_NAMES.timestamp]: String(timestamp),
    "content-type": "application/json",
  });
  if (includeAttestation) {
    headers.set(
      APPLICATION_ATTESTATION_HEADER,
      applicationAttestation(privateKey, material.canonical_string),
    );
  }
  const request = new Request("https://gateway.test/v1/requests", {
    body: JSON.stringify(body),
    headers,
    method: "POST",
  });
  const originalNow = Date.now;
  Date.now = () => NOW;
  try {
    const requester = await authenticateRequester({
      audience: "https://gateway.test",
      body,
      lookupRequester: () => ({
        displayName: "Codex on Mac",
        publicKey: requesterPublicKey,
      }),
      method: "POST",
      path: "/v1/requests",
      request,
      useNonce: () => true,
    });
    if (!await verifyApplicationAttestation({ identity, request, requester })) {
      return {
        assurance: "unverified",
        principalId: null,
        principalScheme: null,
        signingIdentifier: null,
      };
    }
    return {
      assurance: identity.assurance,
      principalId: identity.principal_id,
      principalScheme: identity.principal_scheme,
      signingIdentifier: identity.signing_identifier,
    };
  } finally {
    Date.now = originalNow;
  }
}

function applicationAttestation(
  privateKey: KeyObject,
  requesterCanonicalString: string,
): string {
  const material = formatApplicationAttestationString({
    principal_id: APPLICATION_ID,
    principal_scheme: "macos-designated-requirement-v1",
    requester_canonical_string: requesterCanonicalString,
  });
  return encodeBase64Url(sign(null, Buffer.from(material), privateKey));
}

function rememberedSecretAvailable(application: TestApplication): boolean {
  return rememberedAuthorizationDurationAvailable({
    action: "secret.read",
    applicationAssurance: application.assurance,
    applicationPrincipalId: application.principalId,
    applicationPrincipalScheme: application.principalScheme,
    applicationScopeId: application.principalId,
    applicationSigningIdentifier: application.signingIdentifier,
    decision: "approve",
    duration: "4-hours",
    sshAgentInstancePublicKey: null,
    sshScopeId: null,
    sshScopeKind: null,
  });
}

function insertSecretGrant(
  db: DatabaseSync,
  duration = "4-hours",
): void {
  db.prepare(`INSERT INTO secret_authorization_grants
    (id, requester_device_id, scope_id, client_application,
     application_principal_scheme, application_signing_identifier,
     item_id, item_title, field_id, field_label, field_type, item_version,
     duration, lock_generation, created_at, expires_at, revoked_at,
     authorized_by_credential_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`).run(
    "secret-grant",
    REQUESTER_ID,
    APPLICATION_ID,
    "Codex",
    "macos-designated-requirement-v1",
    "com.openai.codex",
    "item-a",
    "Sentry",
    "password",
    "password",
    "concealed",
    3,
    duration,
    0,
    NOW,
    duration === "until-lock" ? null : NOW + 60_000,
    "passkey-a",
  );
}

function insertSshGrant(db: DatabaseSync): void {
  db.prepare(`INSERT INTO ssh_authorization_grants
    (id, requester_device_id, agent_instance_public_key, scope_id, scope_kind,
     client_application, application_principal_scheme,
     application_signing_identifier, item_id, item_title, item_version,
     fingerprint, duration, lock_generation, created_at, expires_at,
     revoked_at, authorized_by_credential_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`).run(
    "ssh-grant",
    REQUESTER_ID,
    "agent-a",
    APPLICATION_ID,
    "application",
    "Codex",
    "macos-designated-requirement-v1",
    "com.openai.codex",
    "ssh-item",
    "GitHub SSH Key",
    4,
    "SHA256:test",
    "until-agent-quits",
    0,
    NOW,
    "passkey-a",
  );
}

function insertRequest(
  sql: RequestInsertSql,
  input: {
    grantId: string | null;
    id: string;
    kind: "secret" | "ssh";
    status: "approved" | "pending";
  },
): void {
  const ssh = input.kind === "ssh";
  insertProductionRequest(sql, {
    action: ssh ? "ssh.sign" : "secret.read",
    application_assurance: "verified-code-signature",
    application_principal_id: APPLICATION_ID,
    application_principal_scheme: "macos-designated-requirement-v1",
    application_scope_id: ssh ? null : APPLICATION_ID,
    application_signer_name: "OpenAI OpCo, LLC",
    application_signing_identifier: "com.openai.codex",
    application_team_identifier: "2DC432GLL2",
    authorized_until: input.status === "approved" ? NOW + 30_000 : null,
    body_hash: "body-hash",
    client_application: "Codex",
    client_source: "helper",
    consumed_at: null,
    created_at: NOW,
    decided_at: input.status === "approved" ? NOW : null,
    error_code: null,
    execution_started_at: null,
    expected_version: ssh ? 4 : 3,
    expires_at: NOW + 60_000,
    field_id: ssh ? "ssh" : "password",
    field_label: ssh ? "SHA256:test" : "password",
    field_type: ssh ? "ssh-key" : "concealed",
    id: input.id,
    idempotency_key: `idem-${input.id}`,
    item_id: ssh ? "ssh-item" : "item-a",
    item_title: ssh ? "GitHub SSH Key" : "Sentry",
    legacy_ssh_signed_consume: 0,
    requester_device_id: REQUESTER_ID,
    requester_name: "Codex on Mac",
    secret_grant_id: ssh ? null : input.grantId,
    ssh_agent_instance_public_key: ssh ? "agent-a" : null,
    ssh_grant_id: ssh ? input.grantId : null,
    ssh_scope_id: ssh ? APPLICATION_ID : null,
    ssh_scope_kind: ssh ? "application" : null,
    status: input.status,
  });
}

function activeSecretGrant(db: DatabaseSync): string | undefined {
  const runtime = db.prepare(
    "SELECT locked, lock_generation FROM gateway_runtime_state WHERE singleton = 1",
  ).get() as { lock_generation: number; locked: number };
  if (runtime.locked === 1) return undefined;
  return (db.prepare(`SELECT id FROM secret_authorization_grants WHERE
      ${ACTIVE_SECRET_GRANT_LOOKUP_PREDICATE}
      ORDER BY created_at DESC LIMIT 1`).get(
    REQUESTER_ID,
    APPLICATION_ID,
    "item-a",
    "password",
    3,
    NOW,
    runtime.lock_generation,
  ) as { id?: string } | undefined)?.id;
}

function activeSshGrant(
  db: DatabaseSync,
  agentInstance = "agent-a",
  scopeId = APPLICATION_ID,
): string | undefined {
  const runtime = db.prepare(
    "SELECT locked, lock_generation FROM gateway_runtime_state WHERE singleton = 1",
  ).get() as { lock_generation: number; locked: number };
  if (runtime.locked === 1) return undefined;
  return (db.prepare(`SELECT id FROM ssh_authorization_grants WHERE
      ${ACTIVE_SSH_GRANT_LOOKUP_PREDICATE}
      ORDER BY created_at DESC LIMIT 1`).get(
    REQUESTER_ID,
    agentInstance,
    scopeId,
    "application",
    "ssh-item",
    4,
    "SHA256:test",
    NOW,
    runtime.lock_generation,
  ) as { id?: string } | undefined)?.id;
}

function consume(db: DatabaseSync, requestId: string, kind: "secret" | "ssh"): boolean {
  const predicate = kind === "secret"
    ? ACTIVE_SECRET_GRANT_CONSUME_PREDICATE
    : ACTIVE_SSH_GRANT_CONSUME_PREDICATE;
  return db.prepare(`UPDATE requests SET status = 'executing'
    WHERE id = ? AND status = 'approved' AND ${predicate}
    RETURNING id`).all(requestId, NOW).length === 1;
}

test("verified attestation establishes a reusable secret grant whose revoke stops queued execution", async () => {
  const application = await authenticateApplication(true);
  assert.equal(rememberedSecretAvailable(application), true);

  const { database: db, sql } = approvalStorage();
  insertSecretGrant(db);
  assert.equal(activeSecretGrant(db), "secret-grant");
  insertRequest(sql, {
    grantId: activeSecretGrant(db)!,
    id: "automatic-read",
    kind: "secret",
    status: "approved",
  });
  assert.equal(consume(db, "automatic-read", "secret"), true);

  insertRequest(sql, {
    grantId: "secret-grant",
    id: "queued-read",
    kind: "secret",
    status: "approved",
  });
  db.prepare("UPDATE secret_authorization_grants SET revoked_at = ? WHERE id = ?")
    .run(NOW, "secret-grant");
  assert.deepEqual(
    db.prepare(rejectQueuedRequestsForGrantSql("secret"))
      .all(NOW, "secret-grant").map((row) => row.id),
    ["queued-read"],
  );
  assert.equal(consume(db, "queued-read", "secret"), false);
});

test("remembered grant usage starts at zero and counts only explicit successful consumption", () => {
  const { database: db, sql } = approvalStorage();
  insertSecretGrant(db);
  insertSshGrant(db);
  assert.equal(
    (db.prepare("SELECT use_count FROM secret_authorization_grants WHERE id = ?")
      .get("secret-grant") as { use_count: number }).use_count,
    0,
  );
  assert.equal(
    (db.prepare("SELECT use_count FROM ssh_authorization_grants WHERE id = ?")
      .get("ssh-grant") as { use_count: number }).use_count,
    0,
  );
  assert.equal(incrementRememberedGrantUse(sql, "secret", "secret-grant"), true);
  assert.equal(incrementRememberedGrantUse(sql, "secret", "secret-grant"), true);
  assert.equal(incrementRememberedGrantUse(sql, "ssh", "ssh-grant"), true);
  assert.equal(incrementRememberedGrantUse(sql, "ssh", "missing-grant"), false);
  assert.equal(
    (db.prepare("SELECT use_count FROM secret_authorization_grants WHERE id = ?")
      .get("secret-grant") as { use_count: number }).use_count,
    2,
  );
  assert.equal(
    (db.prepare("SELECT use_count FROM ssh_authorization_grants WHERE id = ?")
      .get("ssh-grant") as { use_count: number }).use_count,
    1,
  );
});

test("unverified applications can consume one approval but cannot create or reuse remembered authority", async () => {
  const application = await authenticateApplication(false);
  assert.equal(rememberedSecretAvailable(application), false);

  const { database: db, sql } = approvalStorage();
  insertRequest(sql, {
    grantId: null,
    id: "one-time-read",
    kind: "secret",
    status: "approved",
  });
  assert.equal(consume(db, "one-time-read", "secret"), true);

  insertRequest(sql, {
    grantId: null,
    id: "next-read",
    kind: "secret",
    status: "pending",
  });
  assert.equal(activeSecretGrant(db), undefined);
  assert.equal(consume(db, "next-read", "secret"), false);
});

test("lock mode blocks queued secret work and invalidates until-lock authority across unlock", () => {
  const { database: db, sql } = approvalStorage();
  insertSecretGrant(db, "until-lock");
  insertRequest(sql, {
    grantId: "secret-grant",
    id: "locked-read",
    kind: "secret",
    status: "approved",
  });
  assert.equal(activeSecretGrant(db), "secret-grant");

  db.exec(`UPDATE gateway_runtime_state
    SET locked = 1, lock_generation = lock_generation + 1`);
  assert.equal(activeSecretGrant(db), undefined);
  assert.equal(consume(db, "locked-read", "secret"), false);

  db.exec("UPDATE gateway_runtime_state SET locked = 0");
  assert.equal(activeSecretGrant(db), undefined);
  assert.equal(consume(db, "locked-read", "secret"), false);
});

test("SSH remembered authority binds both the verified application and exact Agent instance", () => {
  assert.equal(rememberedAuthorizationDurationAvailable({
    action: "ssh.sign",
    applicationAssurance: "verified-code-signature",
    applicationPrincipalId: APPLICATION_ID,
    applicationPrincipalScheme: "macos-designated-requirement-v1",
    applicationScopeId: null,
    applicationSigningIdentifier: "com.openai.codex",
    decision: "approve",
    duration: "until-agent-quits",
    sshAgentInstancePublicKey: "agent-a",
    sshScopeId: APPLICATION_ID,
    sshScopeKind: "application",
  }), true);

  const { database: db, sql } = approvalStorage();
  insertSshGrant(db);
  assert.equal(activeSshGrant(db), "ssh-grant");
  assert.equal(activeSshGrant(db, "agent-b"), undefined);
  assert.equal(activeSshGrant(db, "agent-a", "other-application"), undefined);
  insertRequest(sql, {
    grantId: "ssh-grant",
    id: "automatic-sign",
    kind: "ssh",
    status: "approved",
  });
  assert.equal(consume(db, "automatic-sign", "ssh"), true);
  insertRequest(sql, {
    grantId: "ssh-grant",
    id: "queued-sign",
    kind: "ssh",
    status: "approved",
  });
  db.exec("UPDATE ssh_authorization_grants SET agent_instance_public_key = 'agent-b'");
  assert.equal(activeSshGrant(db), undefined);
  assert.equal(consume(db, "queued-sign", "ssh"), false);
});

test("credential and requester revocation reject all queued authority immediately", () => {
  const { database: byCredential, sql: credentialSql } = approvalStorage();
  insertSecretGrant(byCredential);
  insertSshGrant(byCredential);
  insertRequest(credentialSql, {
    grantId: "secret-grant",
    id: "secret-queued",
    kind: "secret",
    status: "approved",
  });
  insertRequest(credentialSql, {
    grantId: "ssh-grant",
    id: "ssh-queued",
    kind: "ssh",
    status: "approved",
  });
  assert.deepEqual(
    byCredential.prepare(REJECT_QUEUED_REQUESTS_FOR_CREDENTIAL_SQL)
      .all(NOW, "passkey-a", "passkey-a")
      .map((row) => row.id).sort(),
    ["secret-queued", "ssh-queued"],
  );
  assert.equal(consume(byCredential, "secret-queued", "secret"), false);
  assert.equal(consume(byCredential, "ssh-queued", "ssh"), false);

  const { database: byRequester, sql: requesterSql } = approvalStorage();
  insertRequest(requesterSql, {
    grantId: null,
    id: "one-time-queued",
    kind: "secret",
    status: "approved",
  });
  assert.deepEqual(
    byRequester.prepare(REJECT_QUEUED_REQUESTS_FOR_REQUESTER_SQL)
      .all(NOW, REQUESTER_ID).map((row) => row.id),
    ["one-time-queued"],
  );
  assert.equal(consume(byRequester, "one-time-queued", "secret"), false);
});
