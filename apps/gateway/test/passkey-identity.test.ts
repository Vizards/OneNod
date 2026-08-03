import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_PASSKEY_LABEL,
  PASSKEY_RP_NAME,
  PASSKEY_USER_DISPLAY_NAME,
  PASSKEY_USER_NAME,
  passkeyPortabilityLabel,
} from "../src/passkey-identity.js";

test("Passkey identity describes the OneNod owner rather than a device", () => {
  assert.equal(PASSKEY_RP_NAME, "OneNod");
  assert.equal(PASSKEY_USER_DISPLAY_NAME, "OneNod owner");
  assert.equal(PASSKEY_USER_NAME, "owner");
  assert.equal(DEFAULT_PASSKEY_LABEL, "Primary passkey");
});

test("Passkey portability distinguishes synced and device-bound credentials", () => {
  assert.equal(passkeyPortabilityLabel("multiDevice", true), "Synced");
  assert.equal(passkeyPortabilityLabel("multiDevice", false), "Sync-capable");
  assert.equal(passkeyPortabilityLabel("singleDevice", false), "Device-bound");
  assert.equal(passkeyPortabilityLabel("futureType", false), "Unknown");
});
