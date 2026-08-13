import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  REVALIDATE_HUMAN_CREDENTIAL_SQL,
  STORE_ACTIVE_REQUESTER_NONCE_SQL,
} from "../src/worker/requester-auth.js";

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE human_credentials (
      id TEXT PRIMARY KEY,
      counter INTEGER NOT NULL,
      device_type TEXT NOT NULL,
      backed_up INTEGER NOT NULL,
      last_used_at INTEGER NOT NULL,
      revoked_at INTEGER
    );
    CREATE TABLE requesters (
      device_id TEXT PRIMARY KEY,
      revoked_at INTEGER
    );
    CREATE TABLE requester_nonces (
      device_id TEXT NOT NULL,
      nonce TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (device_id, nonce)
    );
  `);
  return db;
}

test("Passkey verification cannot commit after credential revocation or counter change", () => {
  for (const mutate of [
    "UPDATE human_credentials SET revoked_at = 10 WHERE id = 'passkey-a'",
    "UPDATE human_credentials SET counter = 8 WHERE id = 'passkey-a'",
  ]) {
    const db = database();
    db.prepare(`INSERT INTO human_credentials
      (id, counter, device_type, backed_up, last_used_at, revoked_at)
      VALUES ('passkey-a', 7, 'singleDevice', 0, 1, NULL)`).run();
    db.exec(mutate);

    const updated = db.prepare(REVALIDATE_HUMAN_CREDENTIAL_SQL).all(
      8,
      "singleDevice",
      0,
      2,
      "passkey-a",
      7,
    );
    assert.equal(updated.length, 0, mutate);
  }
});

test("Passkey verification atomically advances the observed active credential", () => {
  const db = database();
  db.prepare(`INSERT INTO human_credentials
    (id, counter, device_type, backed_up, last_used_at, revoked_at)
    VALUES ('passkey-a', 7, 'singleDevice', 0, 1, NULL)`).run();

  const updated = db.prepare(REVALIDATE_HUMAN_CREDENTIAL_SQL).all(
    8,
    "multiDevice",
    1,
    2,
    "passkey-a",
    7,
  );
  assert.equal(updated.length, 1);
  assert.equal(updated[0]?.id, "passkey-a");
});

test("requester nonce storage fails closed when requester was revoked during verification", () => {
  const db = database();
  db.prepare(
    "INSERT INTO requesters (device_id, revoked_at) VALUES ('requester-a', NULL)",
  ).run();

  const insert = db.prepare(STORE_ACTIVE_REQUESTER_NONCE_SQL);
  const inserted = insert.all("requester-a", "nonce-a", 100, "requester-a");
  assert.equal(inserted.length, 1);
  assert.equal(inserted[0]?.nonce, "nonce-a");

  db.exec("UPDATE requesters SET revoked_at = 10 WHERE device_id = 'requester-a'");
  assert.deepEqual(
    insert.all("requester-a", "nonce-b", 100, "requester-a"),
    [],
  );
});
