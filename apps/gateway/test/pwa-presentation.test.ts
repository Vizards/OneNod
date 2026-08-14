import assert from "node:assert/strict";
import test from "node:test";

import {
  formatCountdown,
  shortIdentifier,
} from "../src/web/utils/presentation-core.js";

test("countdown copy ticks at second precision and expires exactly at the deadline", () => {
  const deadline = "2027-01-01T01:02:03.000Z";
  const deadlineMs = Date.parse(deadline);
  assert.equal(formatCountdown(deadline, deadlineMs - 8_420, "Expires"), "Expires in 00:09");
  assert.equal(formatCountdown(deadline, deadlineMs - 3_600_000, "Ends"), "Ends in 01:00:00");
  assert.equal(formatCountdown(deadline, deadlineMs, "Ends"), "Expired");
});

test("compact identifiers retain both distinguishing ends", () => {
  assert.equal(shortIdentifier("short-value"), "short-value");
  assert.equal(
    shortIdentifier("abcdefghijklmnopqrstuvwxyz"),
    "abcdefgh…uvwxyz",
  );
});
