import assert from "node:assert/strict";
import test from "node:test";

import {
  HUMAN_SESSION_TTL_MS,
  STORAGE_REJECTION_BYTES,
  STORAGE_WARNING_BYTES,
  absoluteHumanSessionExpiry,
  decodeActivityCursor,
  encodeActivityCursor,
  storagePressure,
} from "../src/worker/retention-policy.js";

test("human sessions have one seven-day absolute expiry and never slide", () => {
  const createdAt = Date.UTC(2026, 6, 31, 0, 0, 0);
  const expiresAt = absoluteHumanSessionExpiry(createdAt);

  assert.equal(HUMAN_SESSION_TTL_MS, 7 * 24 * 60 * 60_000);
  assert.equal(expiresAt, Date.UTC(2026, 7, 7, 0, 0, 0));
  // Reading or using the session later has no input to this calculation. The
  // original creation time is the sole authority for expiry.
  assert.equal(absoluteHumanSessionExpiry(createdAt), expiresAt);
});

test("activity cursors preserve the deterministic timestamp and request-id boundary", () => {
  const boundary = {
    createdAt: Date.UTC(2026, 6, 31, 12, 34, 56),
    requestId: "018f1f83-7b2a-7abc-8def-0123456789ab", // gitleaks:allow -- Fixed synthetic UUID test vector.
  };
  const encoded = encodeActivityCursor(boundary);

  assert.match(encoded, /^[A-Za-z0-9_-]+$/u);
  assert.deepEqual(decodeActivityCursor(encoded), boundary);
  assert.throws(() => decodeActivityCursor("not+a+cursor"), /activity_cursor_invalid/u);
  assert.throws(
    () => decodeActivityCursor(encodeActivityCursor({ ...boundary, createdAt: -1 })),
    /activity_cursor_invalid/u,
  );
});

test("storage pressure reserves the final twenty percent for safety transitions", () => {
  assert.equal(storagePressure(STORAGE_WARNING_BYTES - 1), "normal");
  assert.equal(storagePressure(STORAGE_WARNING_BYTES), "warning");
  assert.equal(storagePressure(STORAGE_REJECTION_BYTES - 1), "warning");
  assert.equal(storagePressure(STORAGE_REJECTION_BYTES), "critical");
  assert.equal(storagePressure(Number.NaN), "critical");
  assert.equal(storagePressure(Number.POSITIVE_INFINITY), "critical");
  assert.equal(storagePressure(-1), "critical");
});
