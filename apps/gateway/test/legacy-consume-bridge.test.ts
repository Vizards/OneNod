import assert from "node:assert/strict";
import test from "node:test";

import { initializeApprovalSchema } from "../src/worker/approval-schema.js";
import {
  legacySshSignedConsumeEligible,
  requestPollingAuthorizationAccepted,
} from "../src/worker/legacy-consume-bridge.js";
import { approvalStorage } from "./support/sqlite-do-storage.js";

const POLL_TOKEN = "A".repeat(43);

test("only an SSH request whose signed legacy body omits client identity is bridge eligible", () => {
  const legacyClient = {
    application: "Codex",
    source: "unavailable",
  };

  assert.equal(legacySshSignedConsumeEligible({
    action: "ssh.sign",
    client: legacyClient,
  }), true);
  assert.equal(legacySshSignedConsumeEligible({
    action: "ssh.sign",
    client: {
      ...legacyClient,
      identity: { assurance: "unverified", platform: "macos" },
    },
  }), false);
  assert.equal(legacySshSignedConsumeEligible({
    action: "ssh.sign",
    client: { ...legacyClient, identity: undefined },
  }), false);
  assert.equal(legacySshSignedConsumeEligible({
    action: "secret.read",
    client: legacyClient,
  }), false);
});

test("bearerless consume is confined to one-time legacy SSH approvals", () => {
  const base = {
    action: "ssh.sign",
    authorizationHeader: null,
    expectedToken: POLL_TOKEN,
    legacySshSignedConsume: 1,
    secretGrantId: null,
    sshGrantId: null,
  };
  const cases = [
    { expected: true, input: base, name: "eligible legacy SSH without a header" },
    {
      expected: true,
      input: { ...base, authorizationHeader: `Bearer ${POLL_TOKEN}` },
      name: "the normal polling bearer path remains valid",
    },
    {
      expected: false,
      input: { ...base, authorizationHeader: `Bearer ${"B".repeat(43)}` },
      name: "wrong bearer does not fall back to the bridge",
    },
    {
      expected: false,
      input: { ...base, authorizationHeader: `bearer ${POLL_TOKEN}` },
      name: "malformed authorization does not fall back to the bridge",
    },
    {
      expected: false,
      input: { ...base, legacySshSignedConsume: 0 },
      name: "modern requests require a bearer",
    },
    {
      expected: false,
      input: { ...base, action: "secret.read" },
      name: "secret reads never use the bridge",
    },
    {
      expected: false,
      input: { ...base, sshGrantId: "ssh-grant" },
      name: "remembered SSH authority never uses the bridge",
    },
    {
      expected: false,
      input: { ...base, secretGrantId: "secret-grant" },
      name: "any attached secret authority disables the bridge",
    },
  ] as const;

  for (const entry of cases) {
    assert.equal(
      requestPollingAuthorizationAccepted(entry.input),
      entry.expected,
      entry.name,
    );
  }
});

test("the compatibility flag is fail-closed in the current schema", () => {
  const { database, sql, storage } = approvalStorage();
  const column = database.prepare("PRAGMA table_info(requests)").all()
    .find((entry) => entry.name === "legacy_ssh_signed_consume");

  assert.deepEqual(
    column && {
      defaultValue: column.dflt_value,
      notNull: column.notnull,
      type: column.type,
    },
    { defaultValue: "0", notNull: 1, type: "INTEGER" },
  );

  database.prepare(
    `INSERT INTO requesters
      (device_id, display_name, public_key, created_at, revoked_at)
     VALUES ('new-requester', 'New requester', 'public-key', 1, NULL)`,
  ).run();
  initializeApprovalSchema(storage, sql);
  assert.equal(
    database.prepare(
      "SELECT COUNT(*) AS count FROM legacy_bearerless_ssh_requesters",
    ).get()?.count,
    0,
  );
});
