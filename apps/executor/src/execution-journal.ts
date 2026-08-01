import { isSqliteFullError } from "./storage-policy";

export const EXECUTION_ACTIONS = [
  "item.create",
  "item.patch",
  "item.archive",
] as const;

export const EXECUTION_STATES = [
  "prepared",
  "attempting",
  "applied",
  "definitively_failed",
  "unknown",
] as const;

export const RECONCILE_RESULTS = [
  "APPLIED",
  "NOT_APPLIED",
  "AMBIGUOUS",
  "UNKNOWN",
] as const;

export type ExecutionAction = (typeof EXECUTION_ACTIONS)[number];
export type ExecutionState = (typeof EXECUTION_STATES)[number];
export type ReconcileResult = (typeof RECONCILE_RESULTS)[number];

export interface ExecutionIdentity {
  action: ExecutionAction;
  bodyDigest: string;
  requestId: string;
}

export interface ConfirmedExecutionMetadata {
  itemId?: string;
  version?: number;
}

export interface ExecutionJournalRecord extends ExecutionIdentity {
  attemptStartedAt: number | null;
  completedAt: number | null;
  preparedAt: number;
  reconcileAttemptCount: number;
  reconcileLastAt: number | null;
  reconcileLastResult: ReconcileResult | null;
  resultItemId: string | null;
  resultVersion: number | null;
  revision: number;
  safeCode: string | null;
  state: ExecutionState;
  updatedAt: number;
}

export type WriteInvocationOutcome =
  | {
      metadata?: ConfirmedExecutionMetadata;
      outcome: "applied";
    }
  | {
      outcome: "definitively_failed";
      safeCode: string;
    }
  | {
      outcome: "unknown";
      safeCode: string;
    };

export type ExecutionJournalErrorCode =
  | "confirmed_result_conflict"
  | "identity_conflict"
  | "invalid_action"
  | "invalid_body_digest"
  | "invalid_clock"
  | "invalid_confirmed_metadata"
  | "invalid_reconcile_result"
  | "invalid_request_id"
  | "invalid_safe_code"
  | "journal_concurrent_update"
  | "journal_corrupt"
  | "journal_not_found"
  | "journal_storage_pressure"
  | "journal_transition_invalid"
  | "reconcile_not_allowed"
  | "write_replay_forbidden";

export class ExecutionJournalError extends Error {
  override readonly name = "ExecutionJournalError";

  constructor(readonly code: ExecutionJournalErrorCode) {
    super(code);
  }
}

export interface ExecutionJournalTransaction {
  get(requestId: string): ExecutionJournalRecord | undefined;
  insert(record: ExecutionJournalRecord): boolean;
  replace(
    requestId: string,
    expectedRevision: number,
    record: ExecutionJournalRecord,
  ): boolean;
}

export interface ExecutionJournalStore {
  initialize(): void;
  transact<T>(operation: (transaction: ExecutionJournalTransaction) => T): T;
}

type JournalSqlValue = ArrayBuffer | string | number | null;

interface JournalSqlCursor<
  T extends Record<string, JournalSqlValue>,
> {
  toArray(): T[];
}

interface JournalSqlStorage {
  exec<T extends Record<string, JournalSqlValue>>(
    query: string,
    ...bindings: JournalSqlValue[]
  ): JournalSqlCursor<T>;
}

/** The structural subset of DurableObjectState.storage used by this module. */
export interface DurableObjectSqlStorageLike {
  readonly sql: JournalSqlStorage;
  transactionSync<T>(operation: () => T): T;
}

const TABLE_NAME = "executor_execution_journal";
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BODY_DIGEST_PATTERN = /^(?:[a-f0-9]{64}|[A-Za-z0-9_-]{43})$/;
const ITEM_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const ACTION_SET = new Set<string>(EXECUTION_ACTIONS);
const STATE_SET = new Set<string>(EXECUTION_STATES);
const RECONCILE_RESULT_SET = new Set<string>(RECONCILE_RESULTS);

export class ExecutionJournal {
  readonly #beforeInsert: () => void;
  readonly #clock: () => number;
  readonly #store: ExecutionJournalStore;

  constructor(
    store: ExecutionJournalStore,
    options: { beforeInsert?: () => void; clock?: () => number } = {},
  ) {
    this.#store = store;
    this.#clock = options.clock ?? Date.now;
    this.#beforeInsert = options.beforeInsert ?? (() => undefined);
  }

  initialize(): void {
    this.#store.initialize();
  }

  get(requestId: string): ExecutionJournalRecord | undefined {
    validateRequestId(requestId);
    return this.#store.transact((transaction) => {
      const record = transaction.get(requestId);
      return record === undefined ? undefined : cloneRecord(record);
    });
  }

  prepare(identity: ExecutionIdentity): ExecutionJournalRecord {
    validateIdentity(identity);
    return this.#store.transact((transaction) => {
      const existing = transaction.get(identity.requestId);
      if (existing !== undefined) return requireIdentity(existing, identity);

      this.#beforeInsert();
      const now = this.#now();
      const prepared: ExecutionJournalRecord = {
        action: identity.action,
        attemptStartedAt: null,
        bodyDigest: identity.bodyDigest,
        completedAt: null,
        preparedAt: now,
        reconcileAttemptCount: 0,
        reconcileLastAt: null,
        reconcileLastResult: null,
        resultItemId: null,
        resultVersion: null,
        revision: 0,
        requestId: identity.requestId,
        safeCode: null,
        state: "prepared",
        updatedAt: now,
      };
      if (transaction.insert(prepared)) return cloneRecord(prepared);

      const raced = transaction.get(identity.requestId);
      if (raced === undefined) {
        throw new ExecutionJournalError("journal_concurrent_update");
      }
      return requireIdentity(raced, identity);
    });
  }

  /** Persist this transition synchronously before invoking any upstream write. */
  beginWrite(identity: ExecutionIdentity): ExecutionJournalRecord {
    validateIdentity(identity);
    return this.#transition(identity, (current) => {
      if (current.state !== "prepared") {
        throw new ExecutionJournalError("write_replay_forbidden");
      }
      const now = this.#now();
      return {
        ...current,
        attemptStartedAt: now,
        revision: nextRevision(current.revision),
        state: "attempting",
        updatedAt: now,
      };
    });
  }

  markApplied(
    identity: ExecutionIdentity,
    metadata: ConfirmedExecutionMetadata = {},
  ): ExecutionJournalRecord {
    validateIdentity(identity);
    const safeMetadata = validateConfirmedMetadata(metadata);
    return this.#transition(identity, (current) => {
      if (current.state === "applied") {
        if (
          current.resultItemId !== safeMetadata.itemId ||
          current.resultVersion !== safeMetadata.version
        ) {
          throw new ExecutionJournalError("confirmed_result_conflict");
        }
        return current;
      }
      if (current.state !== "attempting" && current.state !== "unknown") {
        throw new ExecutionJournalError("journal_transition_invalid");
      }
      const now = this.#now();
      return {
        ...current,
        completedAt: now,
        resultItemId: safeMetadata.itemId,
        resultVersion: safeMetadata.version,
        revision: nextRevision(current.revision),
        state: "applied",
        updatedAt: now,
      };
    });
  }

  markDefinitivelyFailed(
    identity: ExecutionIdentity,
    safeCode: string,
  ): ExecutionJournalRecord {
    validateIdentity(identity);
    validateSafeCode(safeCode);
    return this.#transition(identity, (current) => {
      if (current.state === "definitively_failed") {
        if (current.safeCode !== safeCode) {
          throw new ExecutionJournalError("journal_transition_invalid");
        }
        return current;
      }
      if (current.state !== "attempting" && current.state !== "unknown") {
        throw new ExecutionJournalError("journal_transition_invalid");
      }
      const now = this.#now();
      return {
        ...current,
        completedAt: now,
        revision: nextRevision(current.revision),
        safeCode,
        state: "definitively_failed",
        updatedAt: now,
      };
    });
  }

  markUnknown(
    identity: ExecutionIdentity,
    safeCode: string,
  ): ExecutionJournalRecord {
    validateIdentity(identity);
    validateSafeCode(safeCode);
    return this.#transition(identity, (current) => {
      if (current.state === "unknown") {
        if (current.safeCode !== safeCode) {
          throw new ExecutionJournalError("journal_transition_invalid");
        }
        return current;
      }
      if (current.state !== "attempting") {
        throw new ExecutionJournalError("journal_transition_invalid");
      }
      const now = this.#now();
      return {
        ...current,
        revision: nextRevision(current.revision),
        safeCode,
        state: "unknown",
        updatedAt: now,
      };
    });
  }

  recordReconcile(
    identity: ExecutionIdentity,
    result: ReconcileResult,
  ): ExecutionJournalRecord {
    validateIdentity(identity);
    if (!RECONCILE_RESULT_SET.has(result)) {
      throw new ExecutionJournalError("invalid_reconcile_result");
    }
    return this.#transition(identity, (current) => {
      if (current.state !== "attempting" && current.state !== "unknown") {
        throw new ExecutionJournalError("reconcile_not_allowed");
      }
      if (current.reconcileAttemptCount >= Number.MAX_SAFE_INTEGER) {
        throw new ExecutionJournalError("journal_corrupt");
      }
      const now = this.#now();
      return {
        ...current,
        reconcileAttemptCount: current.reconcileAttemptCount + 1,
        reconcileLastAt: now,
        reconcileLastResult: result,
        revision: nextRevision(current.revision),
        updatedAt: now,
      };
    });
  }

  /**
   * The callback is entered only after `attempting` is durable. A thrown or
   * malformed result is conservatively UNKNOWN; it is never retried here.
   */
  async invokeWriteOnce(
    identity: ExecutionIdentity,
    invoke: () => Promise<WriteInvocationOutcome>,
  ): Promise<ExecutionJournalRecord> {
    this.beginWrite(identity);

    let outcome: WriteInvocationOutcome;
    try {
      outcome = await invoke();
    } catch (error) {
      this.#bestEffortUnknown(identity);
      throw error;
    }

    try {
      switch (outcome.outcome) {
        case "applied":
          return this.markApplied(identity, outcome.metadata);
        case "definitively_failed":
          return this.markDefinitivelyFailed(identity, outcome.safeCode);
        case "unknown":
          return this.markUnknown(identity, outcome.safeCode);
      }
    } catch (error) {
      this.#bestEffortUnknown(identity);
      throw error;
    }
  }

  #bestEffortUnknown(identity: ExecutionIdentity): void {
    try {
      const current = this.get(identity.requestId);
      if (current?.state === "attempting") {
        this.markUnknown(identity, "write_outcome_unknown");
      }
    } catch {
      // An unresolved attempting record is already a durable no-replay fence.
    }
  }

  #now(): number {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new ExecutionJournalError("invalid_clock");
    }
    return now;
  }

  #transition(
    identity: ExecutionIdentity,
    update: (current: ExecutionJournalRecord) => ExecutionJournalRecord,
  ): ExecutionJournalRecord {
    return this.#store.transact((transaction) => {
      const loaded = transaction.get(identity.requestId);
      if (loaded === undefined) {
        throw new ExecutionJournalError("journal_not_found");
      }
      const current = requireIdentity(loaded, identity);
      const next = update(current);
      if (next === current) return cloneRecord(current);
      if (!transaction.replace(identity.requestId, current.revision, next)) {
        throw new ExecutionJournalError("journal_concurrent_update");
      }
      return cloneRecord(next);
    });
  }
}

export class SqliteExecutionJournalStore implements ExecutionJournalStore {
  constructor(readonly storage: DurableObjectSqlStorageLike) {}

  initialize(): void {
    this.storage.sql
      .exec(
        `CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
          request_id TEXT PRIMARY KEY,
          action TEXT NOT NULL CHECK (action IN ('item.create', 'item.patch', 'item.archive')),
          body_digest TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('prepared', 'attempting', 'applied', 'definitively_failed', 'unknown')),
          revision INTEGER NOT NULL CHECK (revision >= 0),
          prepared_at INTEGER NOT NULL CHECK (prepared_at >= 0),
          attempt_started_at INTEGER,
          completed_at INTEGER,
          updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
          safe_code TEXT,
          result_item_id TEXT,
          result_version INTEGER CHECK (result_version IS NULL OR result_version >= 0),
          reconcile_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (reconcile_attempt_count >= 0),
          reconcile_last_result TEXT CHECK (reconcile_last_result IS NULL OR reconcile_last_result IN ('APPLIED', 'NOT_APPLIED', 'AMBIGUOUS', 'UNKNOWN')),
          reconcile_last_at INTEGER
        )`,
      )
      .toArray();
  }

  transact<T>(operation: (transaction: ExecutionJournalTransaction) => T): T {
    try {
      return this.storage.transactionSync(() =>
        operation(new SqliteExecutionJournalTransaction(this.storage.sql)),
      );
    } catch (error) {
      if (isSqliteFullError(error)) {
        throw new ExecutionJournalError("journal_storage_pressure");
      }
      throw error;
    }
  }
}

type JournalSqlRow = Record<string, JournalSqlValue> & {
  action: string;
  attempt_started_at: number | null;
  body_digest: string;
  completed_at: number | null;
  prepared_at: number;
  reconcile_attempt_count: number;
  reconcile_last_at: number | null;
  reconcile_last_result: string | null;
  request_id: string;
  result_item_id: string | null;
  result_version: number | null;
  revision: number;
  safe_code: string | null;
  state: string;
  updated_at: number;
};

class SqliteExecutionJournalTransaction implements ExecutionJournalTransaction {
  constructor(readonly sql: JournalSqlStorage) {}

  get(requestId: string): ExecutionJournalRecord | undefined {
    const rows = this.sql
      .exec<JournalSqlRow>(
        `SELECT request_id, action, body_digest, state, revision, prepared_at,
                attempt_started_at, completed_at, updated_at, safe_code,
                result_item_id, result_version, reconcile_attempt_count,
                reconcile_last_result, reconcile_last_at
         FROM ${TABLE_NAME} WHERE request_id = ? LIMIT 1`,
        requestId,
      )
      .toArray();
    const row = rows[0];
    return row === undefined ? undefined : decodeRow(row);
  }

  insert(record: ExecutionJournalRecord): boolean {
    validateStoredRecord(record);
    const rows = this.sql
      .exec<Record<string, JournalSqlValue> & { request_id: string }>(
        `INSERT INTO ${TABLE_NAME}
          (request_id, action, body_digest, state, revision, prepared_at,
           attempt_started_at, completed_at, updated_at, safe_code,
           result_item_id, result_version, reconcile_attempt_count,
           reconcile_last_result, reconcile_last_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(request_id) DO NOTHING
         RETURNING request_id`,
        ...recordBindings(record),
      )
      .toArray();
    return rows.length === 1;
  }

  replace(
    requestId: string,
    expectedRevision: number,
    record: ExecutionJournalRecord,
  ): boolean {
    validateStoredRecord(record);
    if (record.requestId !== requestId) {
      throw new ExecutionJournalError("journal_corrupt");
    }
    const rows = this.sql
      .exec<Record<string, JournalSqlValue> & { request_id: string }>(
        `UPDATE ${TABLE_NAME}
         SET state = ?, revision = ?, prepared_at = ?, attempt_started_at = ?,
             completed_at = ?, updated_at = ?, safe_code = ?, result_item_id = ?,
             result_version = ?, reconcile_attempt_count = ?,
             reconcile_last_result = ?, reconcile_last_at = ?
         WHERE request_id = ? AND revision = ? AND action = ? AND body_digest = ?
         RETURNING request_id`,
        record.state,
        record.revision,
        record.preparedAt,
        record.attemptStartedAt,
        record.completedAt,
        record.updatedAt,
        record.safeCode,
        record.resultItemId,
        record.resultVersion,
        record.reconcileAttemptCount,
        record.reconcileLastResult,
        record.reconcileLastAt,
        record.requestId,
        expectedRevision,
        record.action,
        record.bodyDigest,
      )
      .toArray();
    return rows.length === 1;
  }
}

function recordBindings(record: ExecutionJournalRecord): JournalSqlValue[] {
  return [
    record.requestId,
    record.action,
    record.bodyDigest,
    record.state,
    record.revision,
    record.preparedAt,
    record.attemptStartedAt,
    record.completedAt,
    record.updatedAt,
    record.safeCode,
    record.resultItemId,
    record.resultVersion,
    record.reconcileAttemptCount,
    record.reconcileLastResult,
    record.reconcileLastAt,
  ];
}

function decodeRow(row: JournalSqlRow): ExecutionJournalRecord {
  const record: ExecutionJournalRecord = {
    action: row.action as ExecutionAction,
    attemptStartedAt: row.attempt_started_at,
    bodyDigest: row.body_digest,
    completedAt: row.completed_at,
    preparedAt: row.prepared_at,
    reconcileAttemptCount: row.reconcile_attempt_count,
    reconcileLastAt: row.reconcile_last_at,
    reconcileLastResult: row.reconcile_last_result as ReconcileResult | null,
    requestId: row.request_id,
    resultItemId: row.result_item_id,
    resultVersion: row.result_version,
    revision: row.revision,
    safeCode: row.safe_code,
    state: row.state as ExecutionState,
    updatedAt: row.updated_at,
  };
  validateStoredRecord(record);
  return record;
}

function validateStoredRecord(record: ExecutionJournalRecord): void {
  try {
    validateIdentityFields(record);
    if (!STATE_SET.has(record.state)) throw new Error();
    for (const value of [
      record.preparedAt,
      record.reconcileAttemptCount,
      record.revision,
      record.updatedAt,
    ]) {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error();
    }
    for (const value of [
      record.attemptStartedAt,
      record.completedAt,
      record.reconcileLastAt,
      record.resultVersion,
    ]) {
      if (value !== null && (!Number.isSafeInteger(value) || value < 0)) {
        throw new Error();
      }
    }
    if (record.safeCode !== null) validateSafeCode(record.safeCode);
    if (record.resultItemId !== null && !ITEM_ID_PATTERN.test(record.resultItemId)) {
      throw new Error();
    }
    if (
      record.reconcileLastResult !== null &&
      !RECONCILE_RESULT_SET.has(record.reconcileLastResult)
    ) {
      throw new Error();
    }
    if (
      (record.reconcileAttemptCount === 0) !==
      (record.reconcileLastResult === null && record.reconcileLastAt === null)
    ) {
      throw new Error();
    }
    if (
      (record.state === "prepared" && record.attemptStartedAt !== null) ||
      (record.state !== "prepared" && record.attemptStartedAt === null) ||
      ((record.state === "applied" || record.state === "definitively_failed") &&
        record.completedAt === null) ||
      ((record.state === "prepared" ||
        record.state === "attempting" ||
        record.state === "unknown") &&
        record.completedAt !== null) ||
      (record.state !== "applied" &&
        (record.resultItemId !== null || record.resultVersion !== null))
    ) {
      throw new Error();
    }
  } catch {
    throw new ExecutionJournalError("journal_corrupt");
  }
}

function validateIdentity(identity: ExecutionIdentity): void {
  const keys = Object.keys(identity);
  if (
    keys.length !== 3 ||
    !keys.includes("action") ||
    !keys.includes("bodyDigest") ||
    !keys.includes("requestId")
  ) {
    throw new ExecutionJournalError("identity_conflict");
  }
  validateIdentityFields(identity);
}

function validateIdentityFields(identity: ExecutionIdentity): void {
  validateRequestId(identity.requestId);
  if (!ACTION_SET.has(identity.action)) {
    throw new ExecutionJournalError("invalid_action");
  }
  if (!BODY_DIGEST_PATTERN.test(identity.bodyDigest)) {
    throw new ExecutionJournalError("invalid_body_digest");
  }
}

function validateRequestId(requestId: string): void {
  if (!REQUEST_ID_PATTERN.test(requestId)) {
    throw new ExecutionJournalError("invalid_request_id");
  }
}

function validateSafeCode(safeCode: string): void {
  if (!SAFE_CODE_PATTERN.test(safeCode)) {
    throw new ExecutionJournalError("invalid_safe_code");
  }
}

function validateConfirmedMetadata(
  metadata: ConfirmedExecutionMetadata,
): { itemId: string | null; version: number | null } {
  const keys = Object.keys(metadata);
  if (keys.some((key) => key !== "itemId" && key !== "version")) {
    throw new ExecutionJournalError("invalid_confirmed_metadata");
  }
  const itemId = metadata.itemId ?? null;
  const version = metadata.version ?? null;
  if (
    (itemId !== null && !ITEM_ID_PATTERN.test(itemId)) ||
    (version !== null && (!Number.isSafeInteger(version) || version < 0))
  ) {
    throw new ExecutionJournalError("invalid_confirmed_metadata");
  }
  return { itemId, version };
}

function requireIdentity(
  record: ExecutionJournalRecord,
  identity: ExecutionIdentity,
): ExecutionJournalRecord {
  if (
    record.action !== identity.action ||
    record.bodyDigest !== identity.bodyDigest
  ) {
    throw new ExecutionJournalError("identity_conflict");
  }
  return cloneRecord(record);
}

function nextRevision(revision: number): number {
  if (!Number.isSafeInteger(revision) || revision >= Number.MAX_SAFE_INTEGER) {
    throw new ExecutionJournalError("journal_corrupt");
  }
  return revision + 1;
}

function cloneRecord(record: ExecutionJournalRecord): ExecutionJournalRecord {
  return { ...record };
}
