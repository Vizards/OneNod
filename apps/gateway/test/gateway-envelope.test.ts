import assert from "node:assert/strict";
import test from "node:test";

import {
  sanitizeCatalogEnvelope,
  sanitizeGatewayError,
  sanitizeItemMetadataEnvelope,
  sanitizeItemMutationEnvelope,
  sanitizeItemReconciliationEnvelope,
  sanitizeSecretMetadataEnvelope,
  sanitizeSecretReadEnvelope,
  sanitizeSshSignEnvelope,
} from "../src/worker/gateway-envelope.js";

test("catalog envelope drops unknown data and never accepts field values", () => {
  const result = sanitizeCatalogEnvelope(
    {
      ok: true,
      items: [
        {
          category: "SecureNote",
          fields: [
            {
              field_id: "credential",
              field_type: "Concealed",
              label: "credential",
              value: "must-not-survive",
            },
          ],
          item_id: "item-1",
          title: "dummy",
          updated_at: "2026-07-17T00:00:00.000Z",
          version: 1,
          raw: "must-not-survive",
        },
      ],
    },
    200,
  );
  assert.equal(JSON.stringify(result).includes("must-not-survive"), false);
});

test("catalog envelope rejects unsupported ECDSA SSH metadata", () => {
  assert.throws(() =>
    sanitizeCatalogEnvelope(
      {
        ok: true,
        items: [
          {
            category: "SshKey",
            fields: [],
            item_id: "item-1",
            ssh: {
              algorithm: "ecdsa-sha2-nistp256",
              fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              public_key: "ecdsa-sha2-nistp256 AAAA dummy",
              public_key_blob: "AAAA",
            },
            title: "unsupported",
            updated_at: "2026-07-17T00:00:00.000Z",
            version: 1,
          },
        ],
      },
      200,
    ),
  );
});

test("secret read envelope accepts only a bounded value and safe metadata", () => {
  const result = sanitizeSecretReadEnvelope(
    {
      field_id: "credential",
      field_label: "credential",
      field_type: "Concealed",
      item_id: "item-1",
      item_title: "dummy",
      ok: true,
      value: "dummy-value",
      version: 1,
    },
    200,
    {
      field_id: "credential",
      field_label: "credential",
      field_type: "Concealed",
      item_id: "item-1",
      item_title: "dummy",
      version: 1,
    },
  );
  assert.equal(result.value, "dummy-value");
});

test("secret envelopes reject a response for a different approved target", () => {
  assert.throws(() =>
    sanitizeSecretMetadataEnvelope(
      {
        field_id: "other-field",
        field_label: "credential",
        field_type: "Concealed",
        item_id: "item-1",
        item_title: "dummy",
        ok: true,
        version: 1,
      },
      200,
      { field_id: "credential", item_id: "item-1" },
    ),
  );
});

test("gateway error requires an exact stable code/status pair", () => {
  assert.deepEqual(
    sanitizeGatewayError(
      { error: "onepassword_rate_limited", ok: false },
      429,
    ),
    { code: "onepassword_rate_limited", status: 429 },
  );
  assert.throws(() =>
    sanitizeGatewayError(
      { error: "onepassword_rate_limited", ok: false },
      502,
    ),
  );
});

test("executor storage pressure is accepted only as a 507 safety response", () => {
  assert.deepEqual(
    sanitizeGatewayError(
      { error: "executor_storage_pressure", ok: false },
      507,
    ),
    { code: "executor_storage_pressure", status: 507 },
  );
  assert.throws(
    () =>
      sanitizeGatewayError(
        { error: "executor_storage_pressure", ok: false },
        502,
      ),
    /untrusted_response/u,
  );
});

test("item mutation envelopes pin existing item IDs and strip unknown fields", () => {
  assert.deepEqual(
    sanitizeItemMutationEnvelope(
      { item_id: "item-1", ok: true, raw: "must-not-survive", version: 4 },
      200,
      "item-1",
    ),
    { item_id: "item-1", version: 4 },
  );
  assert.throws(() =>
    sanitizeItemMutationEnvelope(
      { item_id: "different-item", ok: true, version: 4 },
      200,
      "item-1",
    ),
  );
});

test("item metadata and reconciliation envelopes reject mismatched targets", () => {
  assert.equal(
    sanitizeItemMetadataEnvelope(
      {
        item: {
          category: "SecureNote",
          fields: [],
          item_id: "item-1",
          title: "dummy",
          updated_at: "2026-07-17T00:00:00.000Z",
          version: 3,
        },
        ok: true,
      },
      200,
      "item-1",
    ).version,
    3,
  );
  assert.deepEqual(
    sanitizeItemReconciliationEnvelope(
      { item_id: "item-1", ok: true, reconciliation: "APPLIED", version: 4 },
      200,
      "item-1",
    ),
    { item_id: "item-1", reconciliation: "APPLIED", version: 4 },
  );
  assert.throws(() =>
    sanitizeItemReconciliationEnvelope(
      { item_id: "different-item", ok: true, reconciliation: "APPLIED" },
      200,
      "item-1",
    ),
  );
  assert.throws(() =>
    sanitizeItemReconciliationEnvelope(
      { ok: true, reconciliation: "APPLIED" },
      200,
    ),
  );
});

test("unknown 1Password write outcomes require the exact 502 or 504 status", () => {
  assert.deepEqual(
    sanitizeGatewayError(
      { error: "onepassword_write_outcome_unknown", ok: false },
      504,
    ),
    { code: "onepassword_write_outcome_unknown", status: 504 },
  );
  assert.throws(() =>
    sanitizeGatewayError(
      { error: "onepassword_write_outcome_unknown", ok: false },
      409,
    ),
  );
});

test("SSH signature envelopes pin the approved item, version, fingerprint, and algorithm", () => {
  const expected = {
    algorithm: "ssh-ed25519" as const,
    fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    item_id: "item-1",
    version: 3,
  };
  assert.deepEqual(
    sanitizeSshSignEnvelope(
      {
        fingerprint: expected.fingerprint,
        item_id: expected.item_id,
        ok: true,
        public_key_blob: "AQID",
        signature_algorithm: expected.algorithm,
        signature_blob: "BAUG",
        version: expected.version,
      },
      200,
      expected,
    ),
    {
      algorithm: expected.algorithm,
      fingerprint: expected.fingerprint,
      item_id: expected.item_id,
      public_key_blob: "AQID",
      signature_blob: "BAUG",
      version: expected.version,
    },
  );
  assert.throws(() =>
    sanitizeSshSignEnvelope(
      {
        fingerprint: expected.fingerprint,
        item_id: expected.item_id,
        ok: true,
        public_key_blob: "AQID",
        signature_algorithm: "rsa-sha2-512",
        signature_blob: "BAUG",
        version: expected.version,
      },
      200,
      expected,
    ),
  );
});
