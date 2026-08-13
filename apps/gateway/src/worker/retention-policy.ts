import { decodeBase64Url, encodeBase64Url } from "@onenod/protocol";

export const HUMAN_SESSION_TTL_MS = 7 * 24 * 60 * 60_000;

export const ACTIVITY_PAGE_SIZE = 100;
export const ACTIVITY_MAX_RECORDS = 100_000;
export const OPERATIONAL_REQUEST_RETENTION_MS = 7 * 24 * 60 * 60_000;
export const OPERATIONAL_REQUEST_MAX_RECORDS = 10_000;
export const AUDIT_RETENTION_MS = 30 * 24 * 60 * 60_000;
export const AUDIT_MAX_RECORDS = 50_000;
export const REQUESTER_ENROLLMENT_RECEIPT_MS = 5 * 60_000;
export const REVOKED_PWA_DEVICE_RETENTION_MS = 30 * 24 * 60 * 60_000;
export const CLEANUP_BATCH_SIZE = 256;
export const RETENTION_SWEEP_INTERVAL_MS = 6 * 60 * 60_000;

// Cloudflare's Free-limit documentation has described both 1 GB and 10 GB
// per-object ceilings. Until that discrepancy is resolved, use one billion
// bytes (the stricter interpretation of 1 GB) and
// reserve the final 20% for fail-closed transitions and cleanup.
export const CONSERVATIVE_DATABASE_LIMIT_BYTES = 1_000_000_000;
export const STORAGE_WARNING_BYTES = CONSERVATIVE_DATABASE_LIMIT_BYTES * 0.5;
export const STORAGE_REJECTION_BYTES = CONSERVATIVE_DATABASE_LIMIT_BYTES * 0.8;

export type StoragePressure = "normal" | "warning" | "critical";

export interface ActivityCursor {
  createdAt: number;
  requestId: string;
}

export function absoluteHumanSessionExpiry(createdAt: number): number {
  return createdAt + HUMAN_SESSION_TTL_MS;
}

export function storagePressure(databaseSize: number): StoragePressure {
  if (!Number.isFinite(databaseSize) || databaseSize < 0) return "critical";
  if (databaseSize >= STORAGE_REJECTION_BYTES) return "critical";
  if (databaseSize >= STORAGE_WARNING_BYTES) return "warning";
  return "normal";
}

export function encodeActivityCursor(cursor: ActivityCursor): string {
  return encodeBase64Url(
    new TextEncoder().encode(JSON.stringify([cursor.createdAt, cursor.requestId])),
  );
}

export function decodeActivityCursor(value: string): ActivityCursor {
  if (value.length === 0 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new TypeError("activity_cursor_invalid");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
  } catch {
    throw new TypeError("activity_cursor_invalid");
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 2 ||
    !Number.isSafeInteger(parsed[0]) ||
    parsed[0] < 0 ||
    typeof parsed[1] !== "string" ||
    parsed[1].length === 0 ||
    parsed[1].length > 128
  ) {
    throw new TypeError("activity_cursor_invalid");
  }
  return { createdAt: parsed[0], requestId: parsed[1] };
}
