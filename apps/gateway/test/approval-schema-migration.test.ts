import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { initializeApprovalSchema } from "../src/worker/approval-schema.js";
import { approvalStorageAdapters } from "./support/sqlite-do-storage.js";

const NOW = 1_800_000_000_000;

function legacyDatabase(input: {
  requestStatus: "approved" | "consumed" | "executing" | "pending";
}): DatabaseSync {
  const database = new DatabaseSync(":memory:");
  database.exec(`
    CREATE TABLE human_credentials (
      id TEXT PRIMARY KEY, public_key TEXT NOT NULL, counter INTEGER NOT NULL,
      transports TEXT NOT NULL, device_type TEXT NOT NULL,
      backed_up INTEGER NOT NULL, label TEXT NOT NULL,
      created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER
    );
    CREATE TABLE webauthn_challenges (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, challenge TEXT NOT NULL,
      target_id TEXT, decision TEXT, payload TEXT, expires_at INTEGER NOT NULL,
      used_at INTEGER
    );
    CREATE TABLE human_sessions (
      token_hash TEXT PRIMARY KEY, credential_id TEXT NOT NULL, device_id TEXT,
      csrf_token TEXT NOT NULL, created_at INTEGER NOT NULL,
      last_seen_at INTEGER, expires_at INTEGER NOT NULL
    );
    CREATE TABLE human_devices (
      id TEXT PRIMARY KEY, label TEXT NOT NULL, platform TEXT NOT NULL,
      public_key TEXT NOT NULL, created_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL, revoked_at INTEGER
    );
    CREATE TABLE human_device_enrollments (
      id TEXT PRIMARY KEY, device_id TEXT NOT NULL, label TEXT NOT NULL,
      platform TEXT NOT NULL, public_key TEXT NOT NULL,
      public_key_fingerprint TEXT NOT NULL,
      requested_by_credential_id TEXT NOT NULL, status TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      terminal_at INTEGER
    );
    CREATE TABLE push_subscriptions (
      device_id TEXT PRIMARY KEY, endpoint TEXT NOT NULL UNIQUE,
      p256dh TEXT NOT NULL, auth TEXT NOT NULL, expiration_time INTEGER,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      last_success_at INTEGER, failure_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE bootstrap_sessions (
      id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, armed_until INTEGER,
      consumed_at INTEGER
    );
    CREATE TABLE gateway_bootstrap_state (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1), used_at INTEGER NOT NULL
    );
    CREATE TABLE requester_enrollments (
      id TEXT PRIMARY KEY, device_id TEXT NOT NULL, display_name TEXT NOT NULL,
      public_key TEXT NOT NULL, public_key_fingerprint TEXT NOT NULL,
      status TEXT NOT NULL, created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, terminal_at INTEGER
    );
    CREATE TABLE requesters (
      device_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
      public_key TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER
    );
    CREATE TABLE requester_nonces (
      device_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
      PRIMARY KEY (device_id, nonce)
    );
    CREATE TABLE gateway_runtime_state (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1), locked INTEGER NOT NULL,
      lock_generation INTEGER NOT NULL, changed_at INTEGER NOT NULL,
      changed_by TEXT NOT NULL
    );
    CREATE TABLE ssh_authorization_grants (
      id TEXT PRIMARY KEY, requester_device_id TEXT NOT NULL,
      agent_instance_public_key TEXT NOT NULL, scope_id TEXT NOT NULL,
      scope_kind TEXT NOT NULL, item_id TEXT NOT NULL, item_title TEXT NOT NULL,
      item_version INTEGER NOT NULL, fingerprint TEXT NOT NULL,
      duration TEXT NOT NULL, lock_generation INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER,
      authorized_by_credential_id TEXT NOT NULL
    );
    CREATE TABLE requests (
      id TEXT PRIMARY KEY, requester_device_id TEXT NOT NULL,
      requester_name TEXT NOT NULL, action TEXT NOT NULL, item_id TEXT NOT NULL,
      field_id TEXT NOT NULL, expected_version INTEGER NOT NULL,
      client_application TEXT NOT NULL, client_source TEXT NOT NULL,
      ssh_agent_instance_public_key TEXT, ssh_scope_id TEXT, ssh_scope_kind TEXT,
      ssh_grant_id TEXT, item_title TEXT NOT NULL, field_label TEXT NOT NULL,
      field_type TEXT NOT NULL, idempotency_key TEXT NOT NULL,
      body_hash TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, decided_at INTEGER, authorized_until INTEGER,
      execution_started_at INTEGER, consumed_at INTEGER, error_code TEXT,
      UNIQUE (requester_device_id, idempotency_key)
    );
    CREATE TABLE request_operations (
      request_id TEXT PRIMARY KEY, operation_summary TEXT NOT NULL,
      payload_aad TEXT, payload_ciphertext TEXT, payload_digest TEXT,
      payload_iv TEXT, reconcile_state TEXT,
      reconcile_attempt_count INTEGER NOT NULL DEFAULT 0,
      reconcile_attempted_at INTEGER, result_item_id TEXT, result_version INTEGER
    );
    CREATE TABLE request_activity (
      request_id TEXT PRIMARY KEY, action TEXT NOT NULL, status TEXT NOT NULL,
      created_at INTEGER NOT NULL, terminal_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, decided_at INTEGER, consumed_at INTEGER,
      item_title TEXT NOT NULL, field_label TEXT NOT NULL,
      expected_version INTEGER NOT NULL, requester_name TEXT NOT NULL,
      client_application TEXT NOT NULL, client_source TEXT NOT NULL,
      error_code TEXT
    );
    CREATE TABLE gateway_crypto_state (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      generation INTEGER NOT NULL CHECK (generation > 0),
      master_key_fingerprint TEXT NOT NULL, initialized_at INTEGER NOT NULL
    );
    CREATE TABLE gateway_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, request_id TEXT,
      actor_id TEXT, created_at INTEGER NOT NULL
    );
    CREATE TABLE gateway_maintenance_state (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      next_retention_at INTEGER NOT NULL, retention_active INTEGER NOT NULL DEFAULT 0,
      retention_started_at INTEGER, activity_backfill_done INTEGER NOT NULL DEFAULT 0,
      activity_backfill_cursor_created_at INTEGER,
      activity_backfill_cursor_id TEXT, request_trim_done INTEGER NOT NULL DEFAULT 0,
      audit_trim_done INTEGER NOT NULL DEFAULT 0,
      activity_trim_done INTEGER NOT NULL DEFAULT 0,
      request_cutoff_created_at INTEGER, request_cutoff_id TEXT,
      audit_cutoff_created_at INTEGER, audit_cutoff_id INTEGER,
      activity_cutoff_created_at INTEGER, activity_cutoff_id TEXT
    );
    CREATE TABLE gateway_schema_migrations (
      version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL
    );
    CREATE TABLE catalog_metadata_cache (
      cache_key TEXT PRIMARY KEY, value TEXT NOT NULL
    );

    INSERT INTO human_credentials VALUES
      ('passkey-a', 'public-a', 7, '["internal"]', 'multiDevice', 1,
       'Mac passkey', ${NOW - 50_000}, ${NOW - 10_000}, NULL);
    INSERT INTO human_devices VALUES
      ('phone-a', 'iPhone', 'ios', 'device-public-a', ${NOW - 40_000},
       ${NOW - 5_000}, NULL);
    INSERT INTO requesters VALUES
      ('requester-a', 'Codex on Mac', 'requester-public-a', ${NOW - 30_000}, NULL);
    INSERT INTO gateway_runtime_state VALUES (1, 0, 2, ${NOW - 1_000}, 'human');
    INSERT INTO gateway_maintenance_state (singleton, next_retention_at)
      VALUES (1, ${NOW + 60_000});
    INSERT INTO gateway_schema_migrations VALUES (1, ${NOW - 100_000});
    INSERT INTO ssh_authorization_grants VALUES
      ('legacy-grant', 'requester-a', 'agent-a', 'legacy-process-scope',
       'terminal-session', 'ssh-item', 'GitHub SSH Key', 4, 'SHA256:test',
       '4-hours', 2, ${NOW - 1_000}, ${NOW + 60_000}, NULL, 'passkey-a');
    INSERT INTO catalog_metadata_cache VALUES ('old-cache', 'not-authority');
  `);
  database.prepare(`INSERT INTO requests
    (id, requester_device_id, requester_name, action, item_id, field_id,
     expected_version, client_application, client_source,
     ssh_agent_instance_public_key, ssh_scope_id, ssh_scope_kind, ssh_grant_id,
     item_title, field_label, field_type, idempotency_key, body_hash, status,
     created_at, expires_at, decided_at, authorized_until,
     execution_started_at, consumed_at, error_code)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?)`).run(
    "request-a",
    "requester-a",
    "Codex on Mac",
    "ssh.sign",
    "ssh-item",
    "ssh",
    4,
    "Codex",
    "helper",
    "agent-a",
    "legacy-process-scope",
    "terminal-session",
    "legacy-grant",
    "GitHub SSH Key",
    "SHA256:test",
    "ssh-key",
    "idem-a",
    "body-hash-a",
    input.requestStatus,
    NOW - 1_000,
    NOW + 60_000,
    input.requestStatus === "pending" ? null : NOW - 500,
    input.requestStatus === "approved" ? NOW + 30_000 : null,
    input.requestStatus === "executing" ? NOW - 300 : null,
    input.requestStatus === "consumed" ? NOW - 100 : null,
    null,
  );
  database.prepare(`INSERT INTO request_operations
    (request_id, operation_summary, payload_aad, payload_ciphertext,
     payload_digest, payload_iv, reconcile_state)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
    "request-a",
    "Sign with GitHub SSH Key",
    "aad",
    "ciphertext",
    "digest",
    "iv",
    null,
  );
  return database;
}

function alpha20Database(input: {
  requestStatus: "approved" | "consumed" | "executing" | "pending";
}): DatabaseSync {
  const database = legacyDatabase(input);
  database.exec(`
    UPDATE human_credentials
       SET label = 'Primary passkey'
     WHERE id = 'passkey-a';
    INSERT INTO human_sessions VALUES
      ('session-a', 'passkey-a', 'phone-a', 'csrf-a', ${NOW - 20_000},
       ${NOW - 1_000}, ${NOW + 120_000});
    INSERT INTO push_subscriptions VALUES
      ('phone-a', 'https://push.example/subscription-a', 'p256dh-a', 'auth-a',
       NULL, ${NOW - 20_000}, ${NOW - 1_000}, ${NOW - 500}, 0);
    INSERT INTO gateway_schema_migrations VALUES (2, ${NOW - 90_000});
    DROP TABLE catalog_metadata_cache;
  `);
  return database;
}

function preLegacyConsumeBridgeDatabase(
  requestStatus: "approved" | "consumed" | "executing" | "pending" | "unknown",
): DatabaseSync {
  // Reconstruct the schema immediately before the consume bridge. That
  // Gateway accepted alpha.20/protocol-1 request bodies, but did not retain
  // whether client.identity was omitted from the signed body. The migration
  // must therefore drain active rows instead of guessing eligibility.
  const database = alpha20Database({ requestStatus: "consumed" });
  initialize(database);
  database.exec(`
    DELETE FROM gateway_schema_migrations WHERE version = 5;
    DROP TABLE legacy_bearerless_ssh_requesters;
    ALTER TABLE requests DROP COLUMN legacy_ssh_signed_consume;
  `);
  database.prepare(
    `UPDATE requests
        SET status = ?, expires_at = ?, decided_at = ?, authorized_until = ?,
            execution_started_at = ?, consumed_at = ?, error_code = NULL
      WHERE id = 'request-a'`,
  ).run(
    requestStatus,
    NOW + 60_000,
    requestStatus === "pending" ? null : NOW - 500,
    requestStatus === "approved" ? NOW + 30_000 : null,
    requestStatus === "executing" || requestStatus === "unknown"
      ? NOW - 300
      : null,
    requestStatus === "consumed" ? NOW - 100 : null,
  );
  return database;
}

function initialize(database: DatabaseSync): void {
  const { sql, storage } = approvalStorageAdapters(database);
  const originalNow = Date.now;
  Date.now = () => NOW;
  try {
    initializeApprovalSchema(storage, sql);
  } finally {
    Date.now = originalNow;
  }
}

function plain<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function databaseSnapshot(database: DatabaseSync): unknown {
  const schema = database.prepare(
    `SELECT type, name, tbl_name, sql FROM sqlite_schema
     WHERE name NOT LIKE 'sqlite_%'
     ORDER BY type, name`,
  ).all();
  const rows = schema
    .filter((entry) => entry.type === "table")
    .map((entry) => {
      const table = String(entry.name).replaceAll('"', '""');
      return {
        rows: database.prepare(`SELECT * FROM "${table}" ORDER BY rowid`).all(),
        table: entry.name,
      };
    });
  return plain({ rows, schema });
}

function preservedState(database: DatabaseSync): unknown {
  return plain({
    credential: database.prepare(
      "SELECT id, public_key, counter, label, revoked_at FROM human_credentials",
    ).get(),
    humanSession: database.prepare(
      `SELECT token_hash, credential_id, device_id, csrf_token, created_at,
              last_seen_at, expires_at
         FROM human_sessions`,
    ).get(),
    device: database.prepare(
      "SELECT id, label, public_key, revoked_at FROM human_devices",
    ).get(),
    requester: database.prepare(
      "SELECT device_id, display_name, public_key, revoked_at FROM requesters",
    ).get(),
    pushSubscription: database.prepare(
      `SELECT device_id, endpoint, p256dh, auth, expiration_time, created_at,
              updated_at, last_success_at, failure_count
         FROM push_subscriptions`,
    ).get(),
    request: database.prepare(
      "SELECT id, status, item_id, client_application, client_source FROM requests",
    ).get(),
  });
}

test("alpha.20 active requests block before any destructive migration mutation", () => {
  for (const status of ["pending", "approved", "executing"] as const) {
    const database = alpha20Database({ requestStatus: status });
    const before = databaseSnapshot(database);
    assert.throws(
      () => initialize(database),
      /destructive_migration_blocked_by_active_request/u,
      status,
    );
    assert.deepEqual(databaseSnapshot(database), before, status);
  }
});

test("alpha.20 terminal state upgrades while preserving identities and retiring legacy authority", () => {
  const database = alpha20Database({ requestStatus: "consumed" });
  const before = preservedState(database);
  assert.deepEqual(
    database.prepare("SELECT version FROM gateway_schema_migrations ORDER BY version")
      .all().map((row) => row.version),
    [1, 2],
  );
  assert.equal(
    database.prepare(
      "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'catalog_metadata_cache'",
    ).get()?.count,
    0,
  );
  assert.equal(
    (before as { credential: { label: string } }).credential.label,
    "Primary passkey",
  );
  initialize(database);

  assert.equal(
    database.prepare(
      `SELECT COUNT(*) AS count FROM sqlite_master
       WHERE type = 'table' AND name = 'approved_application_identities'`,
    ).get()?.count,
    1,
  );
  assert.equal(
    database.prepare(
      "SELECT COUNT(*) AS count FROM approved_application_identities",
    ).get()?.count,
    0,
  );

  assert.deepEqual(preservedState(database), before);
  assert.equal(
    database.prepare(
      "SELECT legacy_ssh_signed_consume FROM requests WHERE id = 'request-a'",
    ).get()?.legacy_ssh_signed_consume,
    0,
  );
  assert.equal(
    database.prepare("SELECT revoked_at FROM ssh_authorization_grants").get()
      ?.revoked_at,
    NOW,
  );
  assert.equal(
    database.prepare(
      "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'catalog_metadata_cache'",
    ).get()?.count,
    0,
  );
  assert.deepEqual(
    database.prepare("SELECT version FROM gateway_schema_migrations ORDER BY version")
      .all().map((row) => row.version),
    [1, 2, 3, 4, 5],
  );
  assert.equal(
    database.prepare(
      `SELECT expires_at FROM legacy_bearerless_ssh_requesters
        WHERE device_id = 'requester-a'`,
    ).get()?.expires_at,
    NOW + 24 * 60 * 60_000,
  );

  const once = databaseSnapshot(database);
  initialize(database);
  assert.deepEqual(databaseSnapshot(database), once);
});

test("active protocol-1 SSH rows block the consume-bridge migration with zero mutation", () => {
  for (const status of ["pending", "approved", "executing", "unknown"] as const) {
    const database = preLegacyConsumeBridgeDatabase(status);
    const before = databaseSnapshot(database);

    assert.throws(
      () => initialize(database),
      /destructive_migration_blocked_by_active_request/u,
      status,
    );
    assert.deepEqual(databaseSnapshot(database), before, status);
  }
});

test("terminal protocol-1 SSH rows migrate fail-closed after the drain", () => {
  const database = preLegacyConsumeBridgeDatabase("consumed");
  assert.equal(
    database.prepare(
      `SELECT COUNT(*) AS count FROM pragma_table_info('requests')
        WHERE name = 'legacy_ssh_signed_consume'`,
    ).get()?.count,
    0,
  );

  initialize(database);

  assert.equal(
    database.prepare(
      "SELECT legacy_ssh_signed_consume FROM requests WHERE id = 'request-a'",
    ).get()?.legacy_ssh_signed_consume,
    0,
  );
  assert.equal(
    database.prepare(
      `SELECT expires_at FROM legacy_bearerless_ssh_requesters
        WHERE device_id = 'requester-a'`,
    ).get()?.expires_at,
    NOW + 24 * 60 * 60_000,
  );
  assert.deepEqual(
    database.prepare("SELECT version FROM gateway_schema_migrations ORDER BY version")
      .all().map((row) => row.version),
    [1, 2, 3, 4, 5],
  );
});

test("pre-alpha client-observation replacement blocks active work before deleting payloads", () => {
  const database = legacyDatabase({ requestStatus: "pending" });
  database.exec(`
    DROP TABLE requests;
    CREATE TABLE requests (
      id TEXT PRIMARY KEY, requester_device_id TEXT NOT NULL,
      requester_name TEXT NOT NULL, action TEXT NOT NULL, item_id TEXT NOT NULL,
      field_id TEXT NOT NULL, expected_version INTEGER NOT NULL,
      item_title TEXT NOT NULL, field_label TEXT NOT NULL, field_type TEXT NOT NULL,
      idempotency_key TEXT NOT NULL, body_hash TEXT NOT NULL, status TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
      authorized_until INTEGER, execution_started_at INTEGER, consumed_at INTEGER,
      error_code TEXT, UNIQUE (requester_device_id, idempotency_key)
    );
    INSERT INTO requests VALUES
      ('request-a', 'requester-a', 'Codex on Mac', 'secret.read', 'item-a',
       'password', 3, 'Sentry', 'password', 'concealed', 'idem-a', 'body-hash-a',
       'pending', ${NOW - 1000}, ${NOW + 60000}, NULL, NULL, NULL, NULL, NULL);
  `);
  const before = databaseSnapshot(database);

  assert.throws(
    () => initialize(database),
    /destructive_migration_blocked_by_active_request/u,
  );
  assert.deepEqual(databaseSnapshot(database), before);
});
