import { DatabaseSync, type SQLInputValue } from "node:sqlite";

import {
  initializeApprovalSchema,
  type ApprovalSchemaSql,
  type ApprovalSchemaStorage,
} from "../../src/worker/approval-schema.js";

/**
 * Runs the production Durable Object schema against Node's in-memory SQLite.
 *
 * This is intentionally a narrow test adapter rather than a Durable Object
 * fake. Security tests execute the same schema and SQL fragments used by the
 * Worker without adding Miniflare to every unit-test run.
 */
export function approvalStorage(): {
  database: DatabaseSync;
  sql: ApprovalSchemaSql;
  storage: ApprovalSchemaStorage;
} {
  const database = new DatabaseSync(":memory:");
  const adapters = approvalStorageAdapters(database);
  initializeApprovalSchema(adapters.storage, adapters.sql);
  return { database, ...adapters };
}

export function approvalStorageAdapters(database: DatabaseSync): {
  sql: ApprovalSchemaSql;
  storage: ApprovalSchemaStorage;
} {
  const sql = {
    exec(query: string, ...bindings: unknown[]) {
      const values = bindings as SQLInputValue[];
      const returnsRows = values.length > 0 ||
        /^\s*(?:PRAGMA|SELECT|WITH)\b/iu.test(query) ||
        /\bRETURNING\b/iu.test(query);
      const rows = returnsRows
        ? database.prepare(query).all(...values)
        : (database.exec(query), []);
      return {
        toArray() {
          return rows;
        },
      };
    },
  };
  const storage = {
    transactionSync<T>(closure: () => T): T {
      database.exec("BEGIN IMMEDIATE");
      try {
        const value = closure();
        database.exec("COMMIT");
        return value;
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      }
    },
  };
  return {
    sql: sql as unknown as ApprovalSchemaSql,
    storage: storage satisfies ApprovalSchemaStorage,
  };
}
