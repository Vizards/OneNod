import assert from "node:assert/strict";
import test from "node:test";

import ssh2 from "ssh2";

import { CoreAdapterError, type OnePasswordCoreClient } from "../src/onepassword-core.ts";
import {
  GatewayOperationError,
  executeCatalog,
  executeItemArchive,
  executeItemCreate,
  executeItemMetadata,
  executeItemPatch,
  executeSecretRead,
  executeSecretReadMetadata,
  executeSshSign,
  reconcileItemArchive,
  reconcileItemCreate,
  reconcileItemPatch,
  resolveSecret,
} from "../src/onepassword-raw-gateway.ts";
import type {
  OnePasswordOperation,
  WireItem,
  WireItemCreateParams,
} from "../src/onepassword-wire.ts";

const encoder = new TextEncoder();
const vaultId = "a".repeat(26);
const itemId = "b".repeat(26);
const { utils: sshUtils } = ssh2;

test("catalog and metadata return a closed projection without values", async () => {
  const fake = createFakeGateway();
  const items = await executeCatalog({ client: fake.client, query: itemId, vaultId });

  assert.equal(items.length, 1);
  assert.equal(items[0]?.item_id, itemId);
  assert.equal(items[0]?.version, 3);
  assert.deepEqual(
    items[0]?.fields.map((field) => field.field_id),
    ["credential", "com.github.vizards.onenod.notes"],
  );
  assert.equal(JSON.stringify(items).includes("dummy-secret"), false);
  assert.equal(JSON.stringify(items).includes("dummy-notes"), false);

  assert.deepEqual(
    await executeItemMetadata({ client: fake.client, itemId, vaultId }),
    items[0],
  );
  assert.deepEqual(
    await executeSecretReadMetadata({
      client: fake.client,
      fieldId: "credential",
      itemId,
      vaultId,
    }),
    {
      field_id: "credential",
      field_label: "Credential",
      field_type: "Concealed",
      item_id: itemId,
      item_title: "Gateway dummy",
      version: 3,
    },
  );
});

test("secret read and generic secret.resolve freeze scope and item version", async () => {
  const fake = createFakeGateway();
  const result = await executeSecretRead({
    client: fake.client,
    expectedVersion: 3,
    fieldId: "credential",
    itemId,
    vaultId,
  });
  assert.equal(result.value, "dummy-secret");
  assert.equal(
    await resolveSecret({
      client: fake.client,
      fieldId: "credential",
      itemId,
      vaultId,
    }),
    "dummy-secret",
  );

  await assert.rejects(
    executeSecretRead({
      client: fake.client,
      expectedVersion: 2,
      fieldId: "credential",
      itemId,
      vaultId,
    }),
    isGatewayError("item_stale", 409),
  );

  const wrongScope = createFakeGateway({ exposedVaultId: "c".repeat(26) });
  await assert.rejects(
    executeItemMetadata({ client: wrongScope.client, itemId, vaultId }),
    isGatewayError("vault_scope_mismatch", 502),
  );
});

test("SSH catalog and signing resolve only the approved private-key field", async () => {
  const keys = sshUtils.generateKeyPairSync("ed25519");
  const sshItemId = "e".repeat(26);
  const fake = createFakeGateway({
    initialItems: [initialSshItem(sshItemId, keys.public, keys.private)],
  });
  const catalog = await executeCatalog({
    client: fake.client,
    query: sshItemId,
    vaultId,
  });
  const sshInventory = await executeCatalog({
    client: fake.client,
    query: "",
    vaultId,
  });
  assert.equal(sshInventory.length, 1);
  assert.equal(sshInventory[0]?.item_id, sshItemId);
  const metadata = catalog[0]?.ssh;
  assert.ok(metadata);
  assert.equal(metadata.algorithm, "ssh-ed25519");
  assert.equal(JSON.stringify(catalog).includes(keys.private), false);

  const result = await executeSshSign({
    client: fake.client,
    data: encoder.encode("dummy SSH agent payload"),
    expectedFingerprint: metadata.fingerprint,
    expectedVersion: 1,
    itemId: sshItemId,
    requestedAlgorithm: "ssh-ed25519",
    vaultId,
  });
  assert.equal(result.item_id, sshItemId);
  assert.equal(result.fingerprint, metadata.fingerprint);
  assert.equal(result.signature_algorithm, "ssh-ed25519");
  assert.equal(JSON.stringify(result).includes(keys.private), false);
  assert.equal(
    fake.methods.filter((method) => method === "ssh.private-key.resolve").length,
    1,
  );

  await assert.rejects(
    executeSshSign({
      client: fake.client,
      data: new Uint8Array(),
      expectedFingerprint: metadata.fingerprint,
      expectedVersion: 1,
      itemId: sshItemId,
      requestedAlgorithm: "ssh-ed25519",
      vaultId,
    }),
    isGatewayError("ssh_sign_request_invalid", 400),
  );
  assert.equal(
    fake.methods.filter((method) => method === "ssh.private-key.resolve").length,
    1,
  );

  await assert.rejects(
    executeSshSign({
      client: fake.client,
      data: encoder.encode("stale request"),
      expectedFingerprint: metadata.fingerprint,
      expectedVersion: 2,
      itemId: sshItemId,
      requestedAlgorithm: "ssh-ed25519",
      vaultId,
    }),
    isGatewayError("item_stale", 409),
  );
  assert.equal(
    fake.methods.filter((method) => method === "ssh.private-key.resolve").length,
    1,
  );
});

test("create, patch, archive, and their read-only reconciliations match the gateway protocol", async () => {
  const fake = createFakeGateway({ initialItems: [] });
  const requestId = "request-0190f2d8-b0a4-7000-8000-000000000002";
  const created = await executeItemCreate({
    category: "ApiCredentials",
    client: fake.client,
    fields: [
      {
        field_id: "token",
        field_type: "Concealed",
        label: "API token",
        value: "created-secret",
      },
    ],
    requestId,
    title: "Created by gateway",
    vaultId,
  });
  assert.equal(created.version, 1);
  assert.equal(fake.createCount, 1);
  assert.equal(
    fake.items[0]?.fields.find(
      (field) => field.id === "com.github.vizards.onenod.request-id",
    )?.value,
    requestId,
  );
  assert.equal(
    (await reconcileItemCreate({ client: fake.client, requestId, vaultId })).reconciliation,
    "APPLIED",
  );

  const createdItemId = created.item_id;
  const patched = await executeItemPatch({
    client: fake.client,
    expectedVersion: 1,
    itemId: createdItemId,
    operations: [
      { field_id: "token", op: "replace", value: "replacement" },
      {
        field_id: "endpoint",
        field_type: "Url",
        label: "Endpoint",
        op: "add",
        value: "https://example.test",
      },
    ],
    vaultId,
  });
  assert.equal(patched.version, 2);
  assert.equal(fake.putCount, 1);
  assert.equal(
    (
      await reconcileItemPatch({
        client: fake.client,
        expectedVersion: 1,
        itemId: createdItemId,
        operations: [
          { field_id: "token", op: "replace", value: "replacement" },
          {
            field_id: "endpoint",
            field_type: "Url",
            label: "Endpoint",
            op: "add",
            value: "https://example.test",
          },
        ],
        vaultId,
      })
    ).reconciliation,
    "APPLIED",
  );

  assert.deepEqual(
    await executeItemArchive({
      client: fake.client,
      expectedVersion: 2,
      itemId: createdItemId,
      vaultId,
    }),
    { item_id: createdItemId, version: 2 },
  );
  assert.equal(fake.archiveCount, 1);
  assert.equal(
    (
      await reconcileItemArchive({
        client: fake.client,
        expectedVersion: 2,
        itemId: createdItemId,
        vaultId,
      })
    ).reconciliation,
    "APPLIED",
  );
});

test("lost write responses stay UNKNOWN and never replay a mutation", async () => {
  const fake = createFakeGateway({ failAfterWrite: "item.create.raw", initialItems: [] });
  const requestId = "request-response-loss";
  await assert.rejects(
    executeItemCreate({
      category: "SecureNote",
      client: fake.client,
      fields: [
        {
          field_id: "value",
          field_type: "Concealed",
          label: "Value",
          value: "dummy",
        },
      ],
      requestId,
      title: "Unknown create",
      vaultId,
    }),
    isGatewayError("onepassword_write_outcome_unknown", 502),
  );
  assert.equal(fake.createCount, 1);

  fake.failAfterWrite = undefined;
  const reconciled = await reconcileItemCreate({ client: fake.client, requestId, vaultId });
  assert.equal(reconciled.reconciliation, "APPLIED");
  assert.equal(fake.createCount, 1);
});

test("SSH Key create accepts one exact private-key field and generic patch stays forbidden", async () => {
  const fake = createFakeGateway({ initialItems: [] });
  const privateKey =
    "-----BEGIN " + "PRIVATE KEY-----\nZHVtbXk=\n-----END " + "PRIVATE KEY-----\n";
  const created = await executeItemCreate({
    category: "SshKey",
    client: fake.client,
    fields: [
      {
        field_id: "private_key",
        field_type: "SshKey",
        label: "private key",
        value: privateKey,
      },
    ],
    requestId: "request-ssh-create",
    title: "Disposable SSH fixture",
    vaultId,
  });
  const stored = fake.items.find((item) => item.id === created.item_id);
  assert.equal(stored?.category, "SshKey");
  assert.equal(stored?.fields.find((field) => field.id === "private_key")?.value, privateKey);

  await assert.rejects(
    executeItemPatch({
      client: fake.client,
      expectedVersion: 1,
      itemId: created.item_id,
      operations: [{ field_id: "private_key", op: "replace", value: "replacement" }],
      vaultId,
    }),
    isGatewayError("item_operation_invalid", 400),
  );
  assert.equal(fake.putCount, 0);

  for (const fields of [
    [{ field_id: "key", field_type: "SshKey", label: "private key", value: privateKey }],
    [{ field_id: "private_key", field_type: "Concealed", label: "private key", value: privateKey }],
    [{ field_id: "private_key", field_type: "SshKey", label: "Key", value: privateKey }],
  ] as const) {
    await assert.rejects(
      executeItemCreate({
        category: "SshKey",
        client: fake.client,
        fields: fields as never,
        requestId: "request-invalid-ssh-create",
        title: "Invalid SSH fixture",
        vaultId,
      }),
      isGatewayError("item_operation_invalid", 400),
    );
  }
});

test("closed inputs reject unknown fields and reserved field IDs before invoking core", async () => {
  const fake = createFakeGateway({ initialItems: [] });
  await assert.rejects(
    executeItemCreate({
      category: "SecureNote",
      client: fake.client,
      fields: [
        {
          field_id: "com.github.vizards.onenod.injected",
          field_type: "Text",
          label: "Injected",
          value: "dummy",
        },
      ],
      requestId: "request-invalid",
      title: "Invalid",
      vaultId,
    }),
    isGatewayError("item_operation_invalid", 400),
  );
  await assert.rejects(
    executeCatalog({
      client: fake.client,
      query: "dummy",
      vaultId,
      unexpected: true,
    } as never),
    isGatewayError("item_operation_invalid", 400),
  );
  assert.equal(fake.methods.length, 0);
});

interface StoredItem extends WireItem {
  state: "active" | "archived";
}

function createFakeGateway(options: {
  exposedVaultId?: string;
  failAfterWrite?: "item.archive" | "item.create.raw" | "item.put";
  initialItems?: StoredItem[];
} = {}) {
  const exposedVaultId = options.exposedVaultId ?? vaultId;
  const items = options.initialItems ?? [initialItem()];
  const methods: OnePasswordOperation["kind"][] = [];
  let sequence = items.length;
  let createCount = 0;
  let putCount = 0;
  let archiveCount = 0;
  let failAfterWrite = options.failAfterWrite;

  const client = {
    async invoke(operation: OnePasswordOperation): Promise<Uint8Array> {
      methods.push(operation.kind);
      if (operation.kind === "vault.list") {
        return output([{ id: exposedVaultId, title: "test-vault" }]);
      }
      if (operation.kind === "item.list") {
        return output(
          items
            .filter((item) => operation.includeArchived || item.state === "active")
            .map((item) => ({
              category: item.category,
              id: item.id,
              state: item.state,
              tags: item.tags,
              title: item.title,
              updatedAt: item.updatedAt,
              vaultId: item.vaultId,
              websites: item.websites,
            })),
        );
      }
      if (operation.kind === "item.get") {
        const item = items.find((candidate) => candidate.id === operation.itemId);
        assert.ok(item);
        return output(item);
      }
      if (operation.kind === "item.create.raw") {
        createCount += 1;
        sequence += 1;
        const item = itemFromCreate(operation.params, sequence);
        items.push(item);
        if (failAfterWrite === operation.kind) throw coreFailure();
        return output(item);
      }
      if (operation.kind === "item.put") {
        putCount += 1;
        const index = items.findIndex((candidate) => candidate.id === operation.item.id);
        assert.notEqual(index, -1);
        const updated: StoredItem = {
          ...structuredClone(operation.item),
          state: items[index]!.state,
          updatedAt: "2026-07-20T01:00:00.000Z",
          version: operation.item.version + 1,
        };
        items[index] = updated;
        if (failAfterWrite === operation.kind) throw coreFailure();
        return output(updated);
      }
      if (operation.kind === "item.archive") {
        archiveCount += 1;
        const item = items.find((candidate) => candidate.id === operation.itemId);
        assert.ok(item);
        item.state = "archived";
        if (failAfterWrite === operation.kind) throw coreFailure();
        return output(null);
      }
      if (
        operation.kind === "secret.resolve" ||
        operation.kind === "ssh.private-key.resolve"
      ) {
        const item = items.find((candidate) => candidate.id === operation.itemId);
        assert.ok(item);
        const field = item.fields.find((candidate) => candidate.id === operation.fieldId);
        assert.ok(field);
        return output(field.value);
      }
      throw new Error("unexpected operation");
    },
  } as OnePasswordCoreClient;

  return {
    get archiveCount() {
      return archiveCount;
    },
    client,
    get createCount() {
      return createCount;
    },
    get failAfterWrite() {
      return failAfterWrite;
    },
    set failAfterWrite(value) {
      failAfterWrite = value;
    },
    items,
    methods,
    get putCount() {
      return putCount;
    },
  };
}

function initialItem(): StoredItem {
  return {
    category: "SecureNote",
    createdAt: "2026-07-20T00:00:00.000Z",
    fields: [
      {
        fieldType: "Concealed",
        id: "credential",
        title: "Credential",
        value: "dummy-secret",
      },
    ],
    files: [],
    id: itemId,
    notes: "dummy-notes",
    sections: [],
    state: "active",
    tags: [],
    title: "Gateway dummy",
    updatedAt: "2026-07-20T00:00:00.000Z",
    vaultId,
    version: 3,
    websites: [],
  };
}

function initialSshItem(
  id: string,
  publicKey: string,
  privateKey: string,
): StoredItem {
  return {
    category: "SshKey",
    createdAt: "2026-07-20T00:00:00.000Z",
    fields: [
      {
        details: {
          content: { publicKey },
          type: "SshKey",
        },
        fieldType: "SshKey",
        id: "private_key",
        title: "private key",
        value: privateKey,
      },
    ],
    files: [],
    id,
    notes: "",
    sections: [],
    state: "active",
    tags: [],
    title: "Disposable SSH key",
    updatedAt: "2026-07-20T00:00:00.000Z",
    vaultId,
    version: 1,
    websites: [],
  };
}

function itemFromCreate(params: WireItemCreateParams, sequence: number): StoredItem {
  return {
    category: params.category,
    createdAt: "2026-07-20T00:00:00.000Z",
    fields: structuredClone(params.fields),
    files: [],
    id: `${"d".repeat(24)}${String(sequence).padStart(2, "0")}`,
    notes: params.notes ?? "",
    sections: structuredClone(params.sections),
    state: "active",
    tags: structuredClone(params.tags ?? []),
    title: params.title,
    updatedAt: "2026-07-20T00:00:00.000Z",
    vaultId: params.vaultId,
    version: 1,
    websites: structuredClone(params.websites ?? []),
  };
}

function output(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value));
}

function coreFailure(): CoreAdapterError {
  return new CoreAdapterError("operation.invoke", "core_call_failed");
}

function isGatewayError(code: string, status: number) {
  return (error: unknown) =>
    error instanceof GatewayOperationError &&
    error.code === code &&
    error.status === status;
}
