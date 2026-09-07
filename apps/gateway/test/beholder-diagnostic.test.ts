import assert from "node:assert/strict";
import test from "node:test";
import type { BeholderDiagnostic } from "@onenod/protocol";
import { safeClientObservation } from "../src/worker/approval-http.js";
import { insertRequest } from "../src/worker/approval-request-repository.js";
import { ApprovalRequestStore } from "../src/worker/approval-request-store.js";
import {
  projectHumanRequestSummary,
  projectHumanActivitySummary,
} from "../src/worker/approval-projection.js";
import { normalizeRequestSummary } from "../src/web/api-normalizers.js";
import { evaluateBeholderAuthorization } from "../src/worker/beholder-authorization.js";
import { approvalStorage } from "./support/sqlite-do-storage.js";

const diagnostic: BeholderDiagnostic = {
  schema_version: 1,
  trace_id: "0123456789abcdef0123456789abcdef",
  stage: "lease",
  code: "prompt-binding-missing",
  model_called: false,
};

test("diagnostics survive request, activity retention, and PWA projection without changing authority", async () => {
  const client = safeClientObservation({
    application: "Codex",
    source: "unavailable",
    beholder_diagnostic: diagnostic,
  });
  assert.deepEqual(client.beholder_diagnostic, diagnostic);
  const { sql, storage, database } = approvalStorage();
  const now = Date.now();
  insertRequest(sql, {
    id: "fixture-request",
    requester_device_id: "fixture-device",
    requester_name: "Fixture Mac",
    action: "ssh.sign",
    authorization_source: "pending",
    beholder_evidence_id: null,
    beholder_key_id: null,
    client_application: client.application,
    client_source: client.source,
    beholder_diagnostic: JSON.stringify(diagnostic),
    application_assurance: "unverified",
    application_principal_scheme: null,
    application_principal_id: null,
    application_signing_identifier: null,
    application_team_identifier: null,
    application_signer_name: null,
    application_scope_id: null,
    secret_grant_id: null,
    ssh_agent_instance_public_key: null,
    ssh_scope_id: null,
    ssh_scope_kind: null,
    ssh_grant_id: null,
    legacy_ssh_signed_consume: 0,
    item_id: "fixture-key",
    field_id: "",
    expected_version: 1,
    item_title: "Fixture key",
    field_label: "SSH",
    field_type: "SSH_KEY",
    idempotency_key: "fixture-idempotency",
    body_hash: "fixture-hash",
    status: "pending",
    created_at: now,
    expires_at: now + 60000,
    decided_at: null,
    authorized_until: null,
    execution_started_at: null,
    consumed_at: null,
    error_code: null,
  });
  const store = new ApprovalRequestStore({
    ...storage,
    sql,
  } as unknown as DurableObjectStorage);
  const row = store.requestRow("fixture-request");
  assert.equal(row.status, "pending");
  const normalized = normalizeRequestSummary(projectHumanRequestSummary(row));
  assert.deepEqual(normalized.client.beholderDiagnostic, diagnostic);
  assert.equal(normalized.authorizationSource, "pending");
  database.exec(
    "UPDATE requests SET status='rejected', authorization_source='pwa-interactive'",
  );
  assert.equal(store.recordTerminalActivity(row.id), true);
  database.exec("DELETE FROM requests");
  const activity = store.requestActivityRow(row.id)!;
  assert.deepEqual(
    normalizeRequestSummary(projectHumanActivitySummary(activity)).client
      .beholderDiagnostic,
    diagnostic,
  );
  const result = await evaluateBeholderAuthorization({
    semanticBody: { client },
    authorityMode: "dogfood-v1",
    authorityKeysJson: "invalid-config",
    nowSeconds: Math.floor(now / 1000),
    requesterDeviceId: "fixture-device",
    authorization: undefined,
  });
  assert.deepEqual(result, { required: true });
});

test("diagnostic payload accepts only bounded identifiers and no arbitrary task text", () => {
  for (const changed of [
    { code: "a task\nwith text" },
    { trace_id: "A".repeat(32) },
    { stage: "arbitrary" },
    { model_called: "false" },
    { evidence_id: "raw text" },
    { extra: "not allowed" },
  ]) {
    assert.throws(() =>
      safeClientObservation({
        application: "Codex",
        source: "unavailable",
        beholder_diagnostic: { ...diagnostic, ...changed },
      }),
    );
  }
});
