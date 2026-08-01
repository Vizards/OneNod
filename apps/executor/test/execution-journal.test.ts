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

const identity: ExecutionIdentity = {
  action: "item.create",
  bodyDigest: "a".repeat(64),
  requestId: "request-0001",
};

test("prepare is idempotent and freezes action plus body digest", () => {
  const { journal } = setup();
  const first = journal.prepare(identity);
  const repeated = journal.prepare(identity);

  assert.deepEqual(repeated, first);
  assertJournalError(
    () => journal.prepare({ ...identity, action: "item.archive" }),
    "identity_conflict",
  );
  assertJournalError(
    () => journal.prepare({ ...identity, bodyDigest: "b".repeat(64) }),
    "identity_conflict",
  );
  assertJournalError(
    () =>
      journal.prepare({
        ...identity,
        body: "must_not_be_persisted",
      } as ExecutionIdentity),
    "identity_conflict",
  );
});

test("checks storage pressure only before a new permanent journal row", () => {
  const store = new InMemoryExecutionJournalStore();
  let pressure = true;
  let checks = 0;
  const journal = new ExecutionJournal(store, {
    beforeInsert: () => {
      checks += 1;
      if (pressure) throw new ExecutionJournalError("journal_storage_pressure");
    },
  });
  journal.initialize();

  assertJournalError(() => journal.prepare(identity), "journal_storage_pressure");
  assert.equal(journal.get(identity.requestId), undefined);
  pressure = false;
  journal.prepare(identity);
  pressure = true;
  assert.equal(journal.prepare(identity).requestId, identity.requestId);
  assert.equal(checks, 2, "idempotent replays must remain readable above the watermark");
});

test("write callback observes durable attempting before invocation", async () => {
  const { journal } = setup();
  journal.prepare(identity);

  const applied = await journal.invokeWriteOnce(identity, async () => {
    assert.equal(journal.get(identity.requestId)?.state, "attempting");
    return {
      metadata: { itemId: "item_123456789", version: 2 },
      outcome: "applied",
    };
  });

  assert.equal(applied.state, "applied");
  assert.equal(applied.resultItemId, "item_123456789");
  assert.equal(applied.resultVersion, 2);
  assert.equal(applied.revision, 2);
  assertJournalError(
    () => journal.beginWrite(identity),
    "write_replay_forbidden",
  );
});

test("concurrent callers share one durable fence and invoke exactly once", async () => {
  const sharedStore = new InMemoryExecutionJournalStore();
  const firstJournal = createJournal(sharedStore);
  const secondJournal = createJournal(sharedStore);
  firstJournal.prepare(identity);

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let invocationCount = 0;
  const first = firstJournal.invokeWriteOnce(identity, async () => {
    invocationCount += 1;
    await gate;
    return { metadata: { itemId: "item_123456789" }, outcome: "applied" };
  });
  const second = secondJournal.invokeWriteOnce(identity, async () => {
    invocationCount += 1;
    return { metadata: { itemId: "duplicate" }, outcome: "applied" };
  });

  await assert.rejects(second, hasJournalCode("write_replay_forbidden"));
  release();
  assert.equal((await first).state, "applied");
  assert.equal(invocationCount, 1);
});

test("response loss becomes unknown and cannot replay the write", async () => {
  const { journal } = setup();
  journal.prepare(identity);
  let invocationCount = 0;

  await assert.rejects(
    journal.invokeWriteOnce(identity, async () => {
      invocationCount += 1;
      throw new Error("simulated_response_loss");
    }),
    /simulated_response_loss/u,
  );

  const unknown = journal.get(identity.requestId);
  assert.equal(unknown?.state, "unknown");
  assert.equal(unknown?.safeCode, "write_outcome_unknown");
  await assert.rejects(
    journal.invokeWriteOnce(identity, async () => {
      invocationCount += 1;
      return { outcome: "definitively_failed", safeCode: "not_applied" };
    }),
    hasJournalCode("write_replay_forbidden"),
  );
  assert.equal(invocationCount, 1);
});

test("restart preserves attempting as a no-replay state and permits read-only reconcile", async () => {
  const store = new InMemoryExecutionJournalStore();
  const beforeRestart = createJournal(store);
  beforeRestart.prepare(identity);
  beforeRestart.beginWrite(identity);

  const afterRestart = createJournal(store);
  let replayed = false;
  await assert.rejects(
    afterRestart.invokeWriteOnce(identity, async () => {
      replayed = true;
      return { outcome: "applied" };
    }),
    hasJournalCode("write_replay_forbidden"),
  );
  assert.equal(replayed, false);

  const reconciled = afterRestart.recordReconcile(identity, "NOT_APPLIED");
  assert.equal(reconciled.state, "attempting");
  assert.equal(reconciled.reconcileAttemptCount, 1);
  assert.equal(reconciled.reconcileLastResult, "NOT_APPLIED");
  const failed = afterRestart.markDefinitivelyFailed(
    identity,
    "reconciled_not_applied",
  );
  assert.equal(failed.state, "definitively_failed");
  assertJournalError(
    () => afterRestart.beginWrite(identity),
    "write_replay_forbidden",
  );
});

test("unknown reconcile history is counted separately before confirmed application", () => {
  const { journal } = setup();
  journal.prepare(identity);
  journal.beginWrite(identity);
  journal.markUnknown(identity, "response_missing");

  journal.recordReconcile(identity, "UNKNOWN");
  const second = journal.recordReconcile(identity, "APPLIED");
  assert.equal(second.state, "unknown");
  assert.equal(second.reconcileAttemptCount, 2);
  assert.equal(second.reconcileLastResult, "APPLIED");

  const applied = journal.markApplied(identity, {
    itemId: "item_after_reconcile",
    version: 1,
  });
  assert.equal(applied.state, "applied");
  assert.equal(applied.reconcileAttemptCount, 2);
  assertJournalError(
    () => journal.recordReconcile(identity, "APPLIED"),
    "reconcile_not_allowed",
  );
});

test("confirmed result rejects arbitrary or secret-bearing fields", async () => {
  const { journal } = setup();
  journal.prepare(identity);
  const secretCanary = "must_not_be_persisted";

  await assert.rejects(
    journal.invokeWriteOnce(identity, async () => ({
      metadata: {
        itemId: "item_123456789",
        value: secretCanary,
      } as never,
      outcome: "applied",
    })),
    hasJournalCode("invalid_confirmed_metadata"),
  );

  const record = journal.get(identity.requestId);
  assert.equal(record?.state, "unknown");
  assert.doesNotMatch(JSON.stringify(record), new RegExp(secretCanary));
  assert.equal("value" in (record ?? {}), false);
});

test("definitive failure is terminal and same confirmation is idempotent", async () => {
  const { journal } = setup();
  journal.prepare(identity);
  const failed = await journal.invokeWriteOnce(identity, async () => ({
    outcome: "definitively_failed",
    safeCode: "upstream_rejected",
  }));
  assert.equal(failed.state, "definitively_failed");

  assert.deepEqual(
    journal.markDefinitivelyFailed(identity, "upstream_rejected"),
    failed,
  );
  assertJournalError(
    () => journal.beginWrite(identity),
    "write_replay_forbidden",
  );
});

function setup(): { journal: ExecutionJournal; store: InMemoryExecutionJournalStore } {
  const store = new InMemoryExecutionJournalStore();
  return { journal: createJournal(store), store };
}

function createJournal(store: InMemoryExecutionJournalStore): ExecutionJournal {
  let now = 1_700_000_000_000;
  const journal = new ExecutionJournal(store, { clock: () => now++ });
  journal.initialize();
  return journal;
}

class InMemoryExecutionJournalStore implements ExecutionJournalStore {
  readonly #records = new Map<string, ExecutionJournalRecord>();
  #initialized = false;

  initialize(): void {
    this.#initialized = true;
  }

  transact<T>(operation: (transaction: ExecutionJournalTransaction) => T): T {
    assert.equal(this.#initialized, true, "store_not_initialized");
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
        const current = this.#records.get(requestId);
        if (current?.revision !== expectedRevision) return false;
        this.#records.set(requestId, { ...record });
        return true;
      },
    });
  }
}

function assertJournalError(
  operation: () => unknown,
  code: ExecutionJournalError["code"],
): void {
  assert.throws(operation, hasJournalCode(code));
}

function hasJournalCode(code: ExecutionJournalError["code"]) {
  return (error: unknown): boolean => {
    assert.ok(error instanceof ExecutionJournalError);
    assert.equal(error.code, code);
    return true;
  };
}
