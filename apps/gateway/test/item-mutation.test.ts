import assert from "node:assert/strict";
import test from "node:test";

import {
  describeItemMutation,
  mutationExecutorBody,
  parseItemMutationRequest,
} from "../src/worker/item-mutation.js";

const CLIENT = {
  application: "Codex",
  source: "process-ancestry",
};

test("item mutation parser accepts a closed sorted patch schema", () => {
  const parsed = parseItemMutationRequest({
    action: "item.patch",
    expected_version: 3,
    idempotency_key: "request-key",
    client: CLIENT,
    item_id: "item-1",
    operations: [
      { field_id: "alpha", op: "replace", value: "dummy-a" },
      { field_id: "zulu", op: "remove" },
    ],
  });
  assert.equal(parsed.action, "item.patch");
  assert.deepEqual(mutationExecutorBody(parsed, "request-1"), {
    action: "item.patch",
    expected_version: 3,
    item_id: "item-1",
    operations: [
      { field_id: "alpha", op: "replace", value: "dummy-a" },
      { field_id: "zulu", op: "remove" },
    ],
  });
});

test("item mutation parser rejects reserved, duplicate, unsorted, and unknown fields", () => {
  const base = {
    action: "item.create",
    category: "SecureNote",
    fields: [
      { field_id: "value", field_type: "Concealed", label: "Value", value: "dummy" },
    ],
    idempotency_key: "request-key",
    client: CLIENT,
    title: "Dummy item",
  };
  assert.throws(
    () => parseItemMutationRequest({ ...base, unexpected: true }),
    /request_schema_invalid/u,
  );
  assert.throws(
    () =>
      parseItemMutationRequest({
        ...base,
        fields: [
          { field_id: "com.github.vizards.onenod.request-id", field_type: "Text", label: "Marker", value: "x" },
        ],
      }),
    /internal_namespace_reserved/u,
  );
  assert.throws(
    () =>
      parseItemMutationRequest({
        ...base,
        fields: [
          { field_id: "z", field_type: "Text", label: "Z", value: "z" },
          { field_id: "a", field_type: "Text", label: "A", value: "a" },
        ],
      }),
    /field_ids_not_sorted/u,
  );
});

test("human mutation description contains a keyed digest but no field values", () => {
  const parsed = parseItemMutationRequest({
    action: "item.create",
    category: "ApiCredentials",
    fields: [
      { field_id: "token", field_type: "Concealed", label: "API token", value: "dummy-secret" },
    ],
    idempotency_key: "request-key",
    client: CLIENT,
    title: "Dummy API",
  });
  const description = describeItemMutation(parsed, undefined, "keyed-digest");
  assert.equal(JSON.stringify(description).includes("dummy-secret"), false);
  assert.equal(JSON.stringify(description).includes("keyed-digest"), true);
});

test("SSH Key create accepts only the one built-in private-key field and never describes its value", () => {
  const privateKey =
    "-----BEGIN " + "PRIVATE KEY-----\nZHVtbXk=\n-----END " + "PRIVATE KEY-----\n";
  const parsed = parseItemMutationRequest({
    action: "item.create",
    category: "SshKey",
    fields: [
      {
        field_id: "private_key",
        field_type: "SshKey",
        label: "private key",
        value: privateKey,
      },
    ],
    idempotency_key: "request-ssh-key",
    client: CLIENT,
    title: "Disposable RSA fixture",
  });
  const description = describeItemMutation(parsed, undefined, "keyed-digest");
  if (parsed.action !== "item.create") assert.fail("SSH fixture parsed as another action");
  assert.equal(parsed.category, "SshKey");
  assert.equal(JSON.stringify(description).includes(privateKey), false);

  for (const invalid of [
    { ...parsed, category: "SecureNote" },
    { ...parsed, fields: [{ ...parsed.fields[0]!, field_id: "key" }] },
    { ...parsed, fields: [{ ...parsed.fields[0]!, field_type: "Concealed" }] },
    { ...parsed, fields: [{ ...parsed.fields[0]!, label: "Key" }] },
  ]) {
    assert.throws(() => parseItemMutationRequest(invalid), /ssh_key_create_shape_invalid/u);
  }
});

test("SSH Key items cannot be patched through the generic mutation protocol", () => {
  const parsed = parseItemMutationRequest({
    action: "item.patch",
    expected_version: 1,
    idempotency_key: "request-ssh-patch",
    client: CLIENT,
    item_id: "ssh-item",
    operations: [{ field_id: "private_key", op: "replace", value: "replacement" }],
  });
  assert.throws(
    () =>
      describeItemMutation(
        parsed,
        {
          category: "SshKey",
          fields: [{ field_id: "private_key", field_type: "SshKey", label: "private key" }],
          item_id: "ssh-item",
          title: "Disposable SSH key",
          updated_at: "2026-07-20T00:00:00Z",
          version: 1,
        },
        "keyed-digest",
      ),
    /ssh_key_patch_forbidden/u,
  );
});
