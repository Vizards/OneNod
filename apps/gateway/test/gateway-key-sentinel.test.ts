import assert from "node:assert/strict";
import test from "node:test";

import { encodeBase64Url } from "@onenod/protocol";

import {
  GATEWAY_KEY_SENTINEL_GENERATION,
  gatewayMasterKeyFingerprint,
  resolveGatewayKeySentinel,
  type GatewayKeySentinelRecord,
  type GatewayKeySentinelStore,
} from "../src/worker/gateway-key-sentinel.js";

const KEY_A = encodeBase64Url(new Uint8Array(32));
const KEY_B = encodeBase64Url(new Uint8Array(32).fill(1));

class MemorySentinelStore implements GatewayKeySentinelStore {
  encryptedPayloads = false;
  record: GatewayKeySentinelRecord | undefined;
  beforeClaim: (() => void) | undefined;

  claimIfSafe(record: GatewayKeySentinelRecord): boolean {
    this.beforeClaim?.();
    if (this.record || this.encryptedPayloads) return false;
    this.record = structuredClone(record);
    return true;
  }

  hasEncryptedPayloads(): boolean {
    return this.encryptedPayloads;
  }

  read(): GatewayKeySentinelRecord | undefined {
    return this.record ? structuredClone(this.record) : undefined;
  }
}

test("master key fingerprint hashes the decoded random key bytes", async () => {
  assert.equal(
    await gatewayMasterKeyFingerprint(KEY_A),
    "Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU",
  );
  await assert.rejects(
    gatewayMasterKeyFingerprint(encodeBase64Url(new Uint8Array(31))),
    /gateway_master_key_invalid/u,
  );
  await assert.rejects(
    gatewayMasterKeyFingerprint(`${KEY_A}=`),
    /unpadded base64url/u,
  );
});

test("strict sentinel initializes only a fresh state and survives restart", async () => {
  const store = new MemorySentinelStore();
  const initialized = await resolveGatewayKeySentinel({
    masterKey: KEY_A,
    store,
  });
  assert.deepEqual(initialized, {
    initialized: true,
    matches: true,
    reason: "ready",
  });
  assert.equal(store.record?.generation, GATEWAY_KEY_SENTINEL_GENERATION);
  assert.notEqual(store.record?.fingerprint, KEY_A);
  assert.equal(JSON.stringify(store.record).includes(KEY_A), false);

  const restarted = await resolveGatewayKeySentinel({
    masterKey: KEY_A,
    store,
  });
  assert.deepEqual(restarted, initialized);
});

test("missing, invalid, and mismatched keys fail closed without rewriting state", async () => {
  const store = new MemorySentinelStore();
  await resolveGatewayKeySentinel({ masterKey: KEY_A, store });
  const original = store.read();

  assert.deepEqual(
    await resolveGatewayKeySentinel({
      masterKey: undefined,
      store,
    }),
    {
      initialized: true,
      matches: false,
      reason: "missing_key",
    },
  );
  assert.deepEqual(
    await resolveGatewayKeySentinel({
      masterKey: "not-base64url!",
      store,
    }),
    {
      initialized: true,
      matches: false,
      reason: "invalid_key",
    },
  );
  assert.deepEqual(
    await resolveGatewayKeySentinel({ masterKey: KEY_B, store }),
    {
      initialized: true,
      matches: false,
      reason: "mismatch",
    },
  );
  assert.deepEqual(store.read(), original);
});

test("unclaimed ciphertext prevents automatic ownership of an existing DO", async () => {
  const store = new MemorySentinelStore();
  store.encryptedPayloads = true;
  assert.deepEqual(
    await resolveGatewayKeySentinel({ masterKey: KEY_A, store }),
    {
      initialized: false,
      matches: false,
      reason: "unclaimed_ciphertext",
    },
  );
  assert.equal(store.record, undefined);
});

test("an atomic claim race observes the winner and never overwrites it", async () => {
  const store = new MemorySentinelStore();
  const otherFingerprint = await gatewayMasterKeyFingerprint(KEY_B);
  store.beforeClaim = () => {
    store.record = {
      fingerprint: otherFingerprint,
      generation: GATEWAY_KEY_SENTINEL_GENERATION,
    };
  };
  assert.deepEqual(
    await resolveGatewayKeySentinel({ masterKey: KEY_A, store }),
    {
      initialized: true,
      matches: false,
      reason: "mismatch",
    },
  );
  assert.equal(store.record?.fingerprint, otherFingerprint);
});

test("malformed or unknown-generation stored sentinels fail closed", async () => {
  for (const record of [
    { fingerprint: "invalid", generation: GATEWAY_KEY_SENTINEL_GENERATION },
    {
      fingerprint: await gatewayMasterKeyFingerprint(KEY_A),
      generation: GATEWAY_KEY_SENTINEL_GENERATION + 1,
    },
  ]) {
    const store = new MemorySentinelStore();
    store.record = record;
    const state = await resolveGatewayKeySentinel({
      masterKey: KEY_A,
      store,
    });
    assert.deepEqual(state, {
      initialized: true,
      matches: false,
      reason: "stored_state_invalid",
    });
  }
});
