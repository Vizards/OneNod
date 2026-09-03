import assert from "node:assert/strict";
import test from "node:test";

import {
  ExecutionJournal,
  ExecutionJournalError,
  type ExecutionJournalRecord,
  type ExecutionJournalStore,
  type ExecutionJournalTransaction,
  type ExecutionIdentity,
} from "../src/execution-journal.ts";
import { ExecutorRequestError } from "../src/executor-request-error.ts";
import {
  EXECUTOR_BODY_DIGEST_HEADER,
  EXECUTOR_REQUEST_ID_HEADER,
  canonicalJsonSha256Base64Url,
  executeJournaledMutation,
  executeJournaledReconciliation,
  parseHealthRequest,
  parseMutationRequest,
  parseSshSignRequest,
  readExecutionIdentity,
  readJsonObject,
} from "../src/internal-onepassword-api.ts";
import { GatewayOperationError } from "../src/onepassword-raw-gateway.ts";

const createIdentity: ExecutionIdentity = {
  action: "item.create",
  bodyDigest: "a".repeat(43),
  requestId: "request-0001",
};

test("canonical digest matches the gateway sorted JSON contract", async () => {
  assert.equal(
    await canonicalJsonSha256Base64Url({
      b: [2, { y: "雪", x: true }],
      a: 1,
    }),
    "-FdAkzGiesuOb9tABymYBase3E1d2OIrWomccUXeJok",
  );
});

test("execution identity requires both headers, the canonical body digest, and create request ID", async () => {
  const body = {
    action: "item.create",
    category: "Password",
    fields: [
      {
        field_id: "password",
        field_type: "Concealed",
        label: "Password",
        value: "dummy-secret",
      },
    ],
    request_id: "request-identity-1",
    title: "Dummy item",
  };
  const digest = await canonicalJsonSha256Base64Url(body);
  const request = jsonRequest(body, {
    [EXECUTOR_BODY_DIGEST_HEADER]: digest,
    [EXECUTOR_REQUEST_ID_HEADER]: "request-identity-1",
  });

  assert.deepEqual(
    await readExecutionIdentity(request, body, "item.create"),
    {
      action: "item.create",
      bodyDigest: digest,
      requestId: "request-identity-1",
    },
  );

  await assert.rejects(
    readExecutionIdentity(
      jsonRequest(body, {
        [EXECUTOR_BODY_DIGEST_HEADER]: "b".repeat(43),
        [EXECUTOR_REQUEST_ID_HEADER]: "request-identity-1",
      }),
      body,
      "item.create",
    ),
    /execution_body_digest_mismatch/u,
  );
  await assert.rejects(
    readExecutionIdentity(
      jsonRequest(body, {
        [EXECUTOR_BODY_DIGEST_HEADER]: digest,
        [EXECUTOR_REQUEST_ID_HEADER]: "different-request",
      }),
      body,
      "item.create",
    ),
    /execution_identity_invalid/u,
  );
});

test("request parsing rejects non-JSON, oversized, and open mutation bodies", async () => {
  await assert.rejects(
    readJsonObject(
      new Request("https://executor.test/internal", {
        body: "{}",
        headers: { "content-type": "text/plain" },
        method: "POST",
      }),
      16,
    ),
    (error) =>
      error instanceof ExecutorRequestError &&
      error.message === "request_content_type_invalid",
  );
  await assert.rejects(
    readJsonObject(
      new Request("https://executor.test/internal", {
        body: JSON.stringify({ value: "a".repeat(32) }),
        headers: { "content-type": "application/json" },
        method: "POST",
      }),
      16,
    ),
    /request_body_too_large/u,
  );
  assert.throws(
    () =>
      parseMutationRequest({
        action: "item.archive",
        expected_version: 1,
        item_id: "itemabcdefghijklmnop",
        unexpected: true,
      }),
    /request_fields_invalid/u,
  );
});

test("SSH Key create parser accepts only the closed built-in field shape", () => {
  const request = {
    action: "item.create",
    category: "SshKey",
    fields: [
      {
        field_id: "private_key",
        field_type: "SshKey",
        label: "private key",
        value:
          "-----BEGIN " + "PRIVATE KEY-----\ndummy\n-----END " + "PRIVATE KEY-----\n",
      },
    ],
    request_id: "request-ssh-create",
    title: "Disposable SSH fixture",
  };
  assert.deepEqual(parseMutationRequest(request), {
    action: "item.create",
    category: "SshKey",
    fields: request.fields,
    requestId: "request-ssh-create",
    title: "Disposable SSH fixture",
  });
  for (const invalid of [
    { ...request, category: "Login" },
    {
      ...request,
      fields: [{ ...request.fields[0], field_id: "key" }],
    },
    {
      ...request,
      fields: [{ ...request.fields[0], field_type: "Text" }],
    },
  ]) {
    assert.throws(() => parseMutationRequest(invalid));
  }
});

test("health request accepts only the closed empty JSON object", () => {
  assert.doesNotThrow(() => parseHealthRequest({}));
  assert.throws(
    () => parseHealthRequest({ probe: true }),
    /request_fields_invalid/u,
  );
});

test("SSH signing parser accepts only a closed bounded canonical request", () => {
  assert.deepEqual(
    parseSshSignRequest({
      algorithm: "ssh-ed25519",
      data: "ZHVtbXk",
      expected_fingerprint:
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      expected_version: 3,
      item_id: "sshitem00000000000000001",
    }),
    {
      data: new TextEncoder().encode("dummy"),
      expectedFingerprint:
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      expectedVersion: 3,
      itemId: "sshitem00000000000000001",
      requestedAlgorithm: "ssh-ed25519",
    },
  );
  for (const invalid of [
    {
      algorithm: "ssh-rsa",
      data: "ZHVtbXk",
      expected_fingerprint:
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      expected_version: 3,
      item_id: "sshitem00000000000000001",
    },
    {
      algorithm: "ecdsa-sha2-nistp256",
      data: "ZHVtbXk",
      expected_fingerprint:
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      expected_version: 3,
      item_id: "sshitem00000000000000001",
    },
    {
      algorithm: "ssh-ed25519",
      data: "ZHVtbXk=",
      expected_fingerprint:
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      expected_version: 3,
      item_id: "sshitem00000000000000001",
    },
    {
      algorithm: "ssh-ed25519",
      data: "ZHVtbXk",
      expected_fingerprint: "SHA256:invalid",
      expected_version: 3,
      item_id: "sshitem00000000000000001",
    },
    {
      algorithm: "ssh-ed25519",
      data: "ZHVtbXk",
      expected_fingerprint:
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      expected_version: 3,
      item_id: "sshitem00000000000000001",
      unexpected: true,
    },
  ]) {
    assert.throws(() => parseSshSignRequest(invalid));
  }
});

test("a successful mutation is invoked once and replayed from its applied terminal record", async () => {
  const journal = createJournal();
  let invocations = 0;
  const first = await executeJournaledMutation({
    identity: createIdentity,
    invoke: async () => {
      invocations += 1;
      assert.equal(journal.get(createIdentity.requestId)?.state, "attempting");
      return { item_id: "item_abcdefghijklmnop", version: 2 };
    },
    journal,
  });
  const replay = await executeJournaledMutation({
    identity: createIdentity,
    invoke: async () => {
      invocations += 1;
      return { item_id: "must_not_be_called", version: 3 };
    },
    journal,
  });

  assert.deepEqual(first, { item_id: "item_abcdefghijklmnop", version: 2 });
  assert.deepEqual(replay, first);
  assert.equal(invocations, 1);
});

test("storage pressure rejects a new journal identity before invoking 1Password", async () => {
  const journal = new ExecutionJournal(new InMemoryExecutionJournalStore(), {
    beforeInsert: () => {
      throw new ExecutionJournalError("journal_storage_pressure");
    },
  });
  journal.initialize();
  let invoked = false;

  await assert.rejects(
    executeJournaledMutation({
      identity: createIdentity,
      invoke: async () => {
        invoked = true;
        return { item_id: "must_not_be_called" };
      },
      journal,
    }),
    hasGatewayError("executor_storage_pressure", 507),
  );
  assert.equal(invoked, false);
  assert.equal(journal.get(createIdentity.requestId), undefined);
});

test("an unknown write never replays and read-only APPLIED reconciliation closes the journal", async () => {
  const journal = createJournal();
  let writes = 0;
  await assert.rejects(
    executeJournaledMutation({
      identity: createIdentity,
      invoke: async () => {
        writes += 1;
        throw new Error("response_lost");
      },
      journal,
    }),
    hasGatewayError("onepassword_write_outcome_unknown", 502),
  );
  await assert.rejects(
    executeJournaledMutation({
      identity: createIdentity,
      invoke: async () => {
        writes += 1;
        return { item_id: "duplicate_item" };
      },
      journal,
    }),
    hasGatewayError("onepassword_write_outcome_unknown", 502),
  );

  let reconciliations = 0;
  const reconciled = await executeJournaledReconciliation({
    identity: createIdentity,
    invoke: async () => {
      reconciliations += 1;
      return {
        item_id: "item_abcdefghijklmnop",
        reconciliation: "APPLIED",
        version: 2,
      };
    },
    journal,
  });
  const terminal = await executeJournaledReconciliation({
    identity: createIdentity,
    invoke: async () => {
      reconciliations += 1;
      return { reconciliation: "AMBIGUOUS" };
    },
    journal,
  });

  assert.equal(writes, 1);
  assert.equal(reconciliations, 1);
  assert.deepEqual(terminal, reconciled);
  assert.equal(journal.get(createIdentity.requestId)?.state, "applied");
});

test("definitive failures and NOT_APPLIED reconciliation remain no-replay terminals", async () => {
  const journal = createJournal();
  const patchIdentity: ExecutionIdentity = {
    action: "item.patch",
    bodyDigest: "b".repeat(43),
    requestId: "request-patch-1",
  };
  let writes = 0;
  await assert.rejects(
    executeJournaledMutation({
      identity: patchIdentity,
      invoke: async () => {
        writes += 1;
        throw new Error("response_lost");
      },
      journal,
    }),
    hasGatewayError("onepassword_write_outcome_unknown", 502),
  );
  assert.deepEqual(
    await executeJournaledReconciliation({
      identity: patchIdentity,
      invoke: async () => ({
        item_id: "item_abcdefghijklmnop",
        reconciliation: "NOT_APPLIED",
        version: 1,
      }),
      itemId: "item_abcdefghijklmnop",
      journal,
    }),
    {
      item_id: "item_abcdefghijklmnop",
      reconciliation: "NOT_APPLIED",
      version: 1,
    },
  );
  await assert.rejects(
    executeJournaledMutation({
      identity: patchIdentity,
      invoke: async () => {
        writes += 1;
        return { item_id: "item_abcdefghijklmnop", version: 2 };
      },
      journal,
    }),
    hasGatewayError("onepassword_write_outcome_unknown", 502),
  );
  assert.equal(writes, 1);

  const staleIdentity: ExecutionIdentity = {
    action: "item.archive",
    bodyDigest: "c".repeat(43),
    requestId: "request-archive-1",
  };
  await assert.rejects(
    executeJournaledMutation({
      identity: staleIdentity,
      invoke: async () => {
        throw new GatewayOperationError("item_stale", 409);
      },
      journal,
    }),
    hasGatewayError("item_stale", 409),
  );
  await assert.rejects(
    executeJournaledMutation({
      identity: staleIdentity,
      invoke: async () => ({ item_id: "must_not_be_called" }),
      journal,
    }),
    hasGatewayError("item_stale", 409),
  );
});

function jsonRequest(body: unknown, extraHeaders: Record<string, string> = {}): Request {
  return new Request("https://executor.test/internal", {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json", ...extraHeaders },
    method: "POST",
  });
}

function createJournal(): ExecutionJournal {
  const journal = new ExecutionJournal(new InMemoryExecutionJournalStore());
  journal.initialize();
  return journal;
}

class InMemoryExecutionJournalStore implements ExecutionJournalStore {
  readonly #records = new Map<string, ExecutionJournalRecord>();

  initialize(): void {}

  transact<T>(operation: (transaction: ExecutionJournalTransaction) => T): T {
    return operation({
      get: (requestId) => {
        const record = this.#records.get(requestId);
        return record === undefined ? undefined : { ...record };
      },
      insert: (record) => {
        if (this.#records.has(record.requestId)) return false;
        this.#records.set(record.requestId, { ...record });
        return true;
      },
      replace: (requestId, expectedRevision, record) => {
        if (this.#records.get(requestId)?.revision !== expectedRevision) return false;
        this.#records.set(requestId, { ...record });
        return true;
      },
    });
  }
}

function hasGatewayError(code: GatewayOperationError["code"], status: number) {
  return (error: unknown): boolean => {
    assert.ok(error instanceof GatewayOperationError);
    assert.equal(error.code, code);
    assert.equal(error.status, status);
    return true;
  };
}
