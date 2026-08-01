export const EXECUTOR_CONSERVATIVE_DATABASE_BYTES = 1_000_000_000;
export const EXECUTOR_STORAGE_WARNING_BYTES = Math.floor(
  EXECUTOR_CONSERVATIVE_DATABASE_BYTES * 0.5,
);
export const EXECUTOR_STORAGE_CRITICAL_BYTES = Math.floor(
  EXECUTOR_CONSERVATIVE_DATABASE_BYTES * 0.8,
);

export type ExecutorStoragePressure = "normal" | "warning" | "critical";

export function executorStoragePressure(bytes: number): ExecutorStoragePressure {
  if (!Number.isFinite(bytes) || bytes < 0) return "critical";
  if (bytes >= EXECUTOR_STORAGE_CRITICAL_BYTES) return "critical";
  if (bytes >= EXECUTOR_STORAGE_WARNING_BYTES) return "warning";
  return "normal";
}

export function isSqliteFullError(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 3 && current; depth += 1) {
    if (current instanceof Error) {
      if (/SQLITE_FULL|database or disk is full/iu.test(`${current.name} ${current.message}`)) {
        return true;
      }
      current = current.cause;
      continue;
    }
    if (typeof current === "object" && !Array.isArray(current)) {
      const value = current as Record<string, unknown>;
      if (value.code === "SQLITE_FULL") return true;
      current = value.cause;
      continue;
    }
    break;
  }
  return false;
}
