import assert from "node:assert/strict";
import test from "node:test";

import type { DurableObjectSqlStorageLike } from "../src/execution-journal.ts";
import { OnePasswordRateLimitCooldown } from "../src/onepassword-rate-limit-cooldown.ts";

interface TestCooldownRow {
  consecutive_rate_limits: number;
  next_probe_at: number;
  probe_until: number | null;
}

test("ordinary successful traffic performs no cooldown success write", () => {
  const fixture = cooldownFixture({
    consecutive_rate_limits: 0,
    next_probe_at: 0,
    probe_until: null,
  });
  const cooldown = new OnePasswordRateLimitCooldown(fixture.storage);
  const admission = cooldown.beforeOperation(1_000, 30_000);

  assert.equal(admission, "normal");
  assert.equal(fixture.statements.length, 1);
  cooldown.recordSuccess(admission, 1_100, 1_000);
  cooldown.releaseProbe(admission, 1_100, 1_000);
  assert.equal(
    fixture.statements.length,
    1,
    "a normal success must not execute an UPDATE",
  );
});

test("a successful cooldown probe clears only an active cooldown", () => {
  const fixture = cooldownFixture({
    consecutive_rate_limits: 2,
    next_probe_at: 900,
    probe_until: null,
  });
  const cooldown = new OnePasswordRateLimitCooldown(fixture.storage);
  const admission = cooldown.beforeOperation(1_000, 30_000);

  assert.equal(admission, "probe");
  cooldown.recordSuccess(admission, 1_100, 1_000);
  assert.equal(fixture.statements.length, 3);
  assert.match(fixture.statements[2]!, /consecutive_rate_limits > 0/u);
  assert.doesNotMatch(
    fixture.statements[2]!,
    /consecutive_rate_limits = 0 OR/u,
  );
});

test("an active cooldown rejects without reserving a second probe", () => {
  const fixture = cooldownFixture({
    consecutive_rate_limits: 1,
    next_probe_at: 2_000,
    probe_until: null,
  });
  const cooldown = new OnePasswordRateLimitCooldown(fixture.storage);

  assert.equal(cooldown.beforeOperation(1_000, 30_000), "rejected");
  assert.equal(fixture.statements.length, 1);
});

function cooldownFixture(row: TestCooldownRow): {
  statements: string[];
  storage: DurableObjectSqlStorageLike;
} {
  const statements: string[] = [];
  const storage = {
    sql: {
      exec(query: string) {
        statements.push(query);
        if (query.includes("SELECT consecutive_rate_limits")) {
          return { toArray: () => [{ ...row }] };
        }
        if (query.includes("RETURNING singleton")) {
          return { toArray: () => [{ singleton: 1 }] };
        }
        return { toArray: () => [] };
      },
    },
    transactionSync<T>(operation: () => T): T {
      return operation();
    },
  } as unknown as DurableObjectSqlStorageLike;
  return { statements, storage };
}
