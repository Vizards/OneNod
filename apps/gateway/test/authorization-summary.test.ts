/// <reference types="@cloudflare/workers-types" />

import assert from "node:assert/strict";
import test from "node:test";

import type {} from "../src/worker/env.js";
import { HumanManagement } from "../src/worker/human-management.js";
import { approvalStorage } from "./support/sqlite-do-storage.js";

const NOW = 1_786_633_200_000;

test("remembered-access summary counts only active grants and reports the next expiry", async () => {
  const { database, sql } = approvalStorage();
  insertSecretGrant(database, "secret-active", NOW + 30_000, null, "4-hours", 7);
  insertSecretGrant(database, "secret-expired", NOW - 1, null, "4-hours", 7);
  insertSshGrant(database, "ssh-active", null, null, "until-lock", 7);
  insertSshGrant(database, "ssh-old-lock", null, null, "until-lock", 6);
  insertSshGrant(database, "ssh-revoked", null, NOW - 1_000, "until-agent-quits", 7);

  const human = {
    gatewayRuntimeState: () => ({ lock_generation: 7 }),
    requireHumanSession: async () => ({ credential_id: "passkey-a" }),
  };
  const management = new HumanManagement(
    { storage: { sql } } as unknown as DurableObjectState,
    {} as Env,
    human as never,
    {} as never,
    {} as never,
    { assertStorageGrowthAllowed() {}, audit() {} },
  );
  const originalNow = Date.now;
  Date.now = () => NOW;
  try {
    const response = await management.authorizationSummary(
      new Request("https://gateway.example/v1/human/authorizations/summary"),
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      active_count: 2,
      next_expiry_at: new Date(NOW + 30_000).toISOString(),
      server_time: new Date(NOW).toISOString(),
    });
  } finally {
    Date.now = originalNow;
  }
});

function insertSecretGrant(
  database: ReturnType<typeof approvalStorage>["database"],
  id: string,
  expiresAt: number | null,
  revokedAt: number | null,
  duration: "4-hours" | "until-lock",
  lockGeneration: number,
): void {
  database.prepare(`INSERT INTO secret_authorization_grants
    (id, requester_device_id, scope_id, client_application,
     application_principal_scheme, application_signing_identifier,
     item_id, item_title, field_id, field_label, field_type, item_version,
     duration, lock_generation, created_at, expires_at, revoked_at,
     authorized_by_credential_id)
    VALUES (?, 'requester-a', 'scope-a', 'Codex',
      'macos-designated-requirement-v1', 'com.openai.codex',
      'item-a', 'Example', 'field-a', 'Password', 'concealed', 1,
      ?, ?, ?, ?, ?, 'passkey-a')`).run(
    id,
    duration,
    lockGeneration,
    NOW - 60_000,
    expiresAt,
    revokedAt,
  );
}

function insertSshGrant(
  database: ReturnType<typeof approvalStorage>["database"],
  id: string,
  expiresAt: number | null,
  revokedAt: number | null,
  duration: "until-agent-quits" | "until-lock",
  lockGeneration: number,
): void {
  database.prepare(`INSERT INTO ssh_authorization_grants
    (id, requester_device_id, agent_instance_public_key, scope_id, scope_kind,
     client_application, application_principal_scheme,
     application_signing_identifier, item_id, item_title, item_version,
     fingerprint, duration, lock_generation, created_at, expires_at,
     revoked_at, authorized_by_credential_id)
    VALUES (?, 'requester-a', 'agent-a', 'scope-a', 'application',
      'Codex', 'macos-designated-requirement-v1', 'com.openai.codex',
      'ssh-a', 'GitHub key', 1, 'SHA256:test', ?, ?, ?, ?, ?, 'passkey-a')`).run(
    id,
    duration,
    lockGeneration,
    NOW - 60_000,
    expiresAt,
    revokedAt,
  );
}
