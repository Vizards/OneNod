import type { DurableObjectSqlStorageLike } from "./execution-journal";

const RATE_LIMIT_DELAYS_MS = [
  60_000,
  5 * 60_000,
  15 * 60_000,
  60 * 60_000,
] as const;

interface CooldownRow {
  consecutive_rate_limits: number;
  next_probe_at: number;
  probe_until: number | null;
}

export type RateLimitCooldownAdmission = "normal" | "probe" | "rejected";

/**
 * Durable, non-secret circuit breaker for the singleton 1Password Executor.
 * It suppresses repeated Service Account probes after an exact upstream 429;
 * it is not a quota estimator and never changes non-429 failures into 429s.
 */
export class OnePasswordRateLimitCooldown {
  constructor(private readonly storage: DurableObjectSqlStorageLike) {}

  initialize(): void {
    this.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS onepassword_rate_limit_cooldown (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        consecutive_rate_limits INTEGER NOT NULL DEFAULT 0,
        next_probe_at INTEGER NOT NULL DEFAULT 0,
        probe_until INTEGER,
        updated_at INTEGER NOT NULL
      )`,
    );
    this.storage.sql.exec(
      `INSERT OR IGNORE INTO onepassword_rate_limit_cooldown
        (singleton, consecutive_rate_limits, next_probe_at, probe_until, updated_at)
       VALUES (1, 0, 0, NULL, ?)`,
      Date.now(),
    );
  }

  /** Distinguishes ordinary traffic from the one request holding a probe lease. */
  beforeOperation(now: number, probeLeaseMs: number): RateLimitCooldownAdmission {
    return this.storage.transactionSync(() => {
      const row = this.row();
      if (row.consecutive_rate_limits === 0) return "normal";
      if (row.next_probe_at > now || (row.probe_until ?? 0) > now) {
        return "rejected";
      }
      const reserved = this.storage.sql.exec(
        `UPDATE onepassword_rate_limit_cooldown
         SET probe_until = ?, updated_at = ?
         WHERE singleton = 1 AND consecutive_rate_limits > 0
           AND next_probe_at <= ?
           AND (probe_until IS NULL OR probe_until <= ?)
         RETURNING singleton`,
        now + probeLeaseMs,
        now,
        now,
        now,
      ).toArray();
      return reserved.length === 1 ? "probe" : "rejected";
    });
  }

  recordSuccess(
    admission: RateLimitCooldownAdmission,
    now: number,
    operationStartedAt: number,
  ): void {
    if (admission !== "probe") return;
    this.storage.sql.exec(
      `UPDATE onepassword_rate_limit_cooldown
       SET consecutive_rate_limits = 0, next_probe_at = 0,
           probe_until = NULL, updated_at = ?
       WHERE singleton = 1
         AND consecutive_rate_limits > 0 AND next_probe_at <= ?`,
      now,
      operationStartedAt,
    );
  }

  recordRateLimit(now: number, operationStartedAt: number): void {
    this.storage.transactionSync(() => {
      const row = this.row();
      // Concurrent operations may all observe the same upstream incident.
      // Once one of them has opened a future cooldown, the rest must not turn
      // that single wave into four artificial "consecutive" probes.
      if (
        row.consecutive_rate_limits > 0 &&
        row.next_probe_at > operationStartedAt
      ) {
        return;
      }
      const current = row.consecutive_rate_limits;
      const next = Math.min(current + 1, RATE_LIMIT_DELAYS_MS.length);
      const delay = RATE_LIMIT_DELAYS_MS[next - 1]!;
      this.storage.sql.exec(
        `UPDATE onepassword_rate_limit_cooldown
         SET consecutive_rate_limits = ?, next_probe_at = ?,
             probe_until = NULL, updated_at = ?
         WHERE singleton = 1`,
        next,
        now + delay,
        now,
      );
    });
  }

  releaseProbe(
    admission: RateLimitCooldownAdmission,
    now: number,
    operationStartedAt: number,
  ): void {
    if (admission !== "probe") return;
    this.storage.sql.exec(
      `UPDATE onepassword_rate_limit_cooldown
       SET probe_until = NULL, updated_at = ?
       WHERE singleton = 1 AND consecutive_rate_limits > 0
         AND next_probe_at <= ?`,
      now,
      operationStartedAt,
    );
  }

  private row(): CooldownRow {
    const row = this.storage.sql.exec(
      `SELECT consecutive_rate_limits, next_probe_at, probe_until
       FROM onepassword_rate_limit_cooldown WHERE singleton = 1`,
    ).toArray()[0] as unknown as CooldownRow | undefined;
    if (!row) throw new Error("onepassword_rate_limit_cooldown_missing");
    return row;
  }
}
