import {
  decodeBase64Url,
  sha256Base64Url,
} from "@onenod/protocol";

export const GATEWAY_KEY_SENTINEL_GENERATION = 1;

export interface GatewayKeySentinelRecord {
  fingerprint: string;
  generation: number;
}

export interface GatewayKeySentinelStore {
  claimIfSafe(record: GatewayKeySentinelRecord): boolean;
  hasEncryptedPayloads(): boolean;
  read(): GatewayKeySentinelRecord | undefined;
}

export type GatewayKeySentinelReason =
  | "invalid_key"
  | "missing_key"
  | "mismatch"
  | "ready"
  | "stored_state_invalid"
  | "unclaimed_ciphertext";

export interface GatewayKeySentinelState {
  initialized: boolean;
  matches: boolean;
  reason: GatewayKeySentinelReason;
}

export async function resolveGatewayKeySentinel(options: {
  masterKey: string | undefined;
  store: GatewayKeySentinelStore;
}): Promise<GatewayKeySentinelState> {
  const existing = options.store.read();
  if (!options.masterKey) {
    return {
      initialized: Boolean(existing),
      matches: false,
      reason: "missing_key",
    };
  }

  let fingerprint: string;
  try {
    fingerprint = await gatewayMasterKeyFingerprint(options.masterKey);
  } catch {
    return {
      initialized: Boolean(existing),
      matches: false,
      reason: "invalid_key",
    };
  }

  if (existing) {
    return compareStoredSentinel(existing, fingerprint);
  }
  if (options.store.hasEncryptedPayloads()) {
    return {
      initialized: false,
      matches: false,
      reason: "unclaimed_ciphertext",
    };
  }

  options.store.claimIfSafe({
    fingerprint,
    generation: GATEWAY_KEY_SENTINEL_GENERATION,
  });
  const claimed = options.store.read();
  if (!claimed) {
    return {
      initialized: false,
      matches: false,
      reason: options.store.hasEncryptedPayloads()
        ? "unclaimed_ciphertext"
        : "stored_state_invalid",
    };
  }
  return compareStoredSentinel(claimed, fingerprint);
}

export async function gatewayMasterKeyFingerprint(
  masterKey: string,
): Promise<string> {
  const raw = decodeBase64Url(masterKey);
  if (raw.byteLength !== 32) {
    throw new TypeError("gateway_master_key_invalid");
  }
  return sha256Base64Url(raw);
}

function compareStoredSentinel(
  record: GatewayKeySentinelRecord,
  fingerprint: string,
): GatewayKeySentinelState {
  if (
    record.generation !== GATEWAY_KEY_SENTINEL_GENERATION ||
    !isFingerprint(record.fingerprint)
  ) {
    return {
      initialized: true,
      matches: false,
      reason: "stored_state_invalid",
    };
  }
  const matches = constantTimeEqual(record.fingerprint, fingerprint);
  return {
    initialized: true,
    matches,
    reason: matches ? "ready" : "mismatch",
  };
}

function isFingerprint(value: string): boolean {
  try {
    return decodeBase64Url(value).byteLength === 32;
  } catch {
    return false;
  }
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.byteLength, rightBytes.byteLength);
  let difference = leftBytes.byteLength ^ rightBytes.byteLength;
  for (let index = 0; index < length; index += 1) {
    difference |=
      (leftBytes[index] ?? 0) ^
      (rightBytes[index] ?? 0);
  }
  return difference === 0;
}
