import {
  canonicalizeJson,
  decodeBase64Url,
  encodeBase64Url,
} from "@onenod/protocol";

const AEAD_INFO = "pending-payload-aead-v1";
const DIGEST_INFO = "payload-digest-hmac-v1";

export interface PendingPayloadContext {
  action: "item.create" | "item.patch" | "ssh.sign";
  environment: "dev" | "prod";
  expiresAt: number;
  requestId: string;
  requesterDeviceId: string;
}

export interface EncryptedPendingPayload {
  aad: string;
  ciphertext: string;
  digest: string;
  iv: string;
}

export async function encryptPendingPayload(
  masterKey: string,
  context: PendingPayloadContext,
  payload: unknown,
): Promise<EncryptedPendingPayload> {
  const plaintext = new TextEncoder().encode(canonicalizeJson(payload));
  const aad = canonicalizeJson(pendingPayloadAad(context));
  const aadBytes = new TextEncoder().encode(aad);
  const { aeadKey, digestKey } = await deriveKeys(masterKey, context.environment);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const [ciphertext, digest] = await Promise.all([
    crypto.subtle.encrypt(
      { additionalData: aadBytes, iv, name: "AES-GCM", tagLength: 128 },
      aeadKey,
      plaintext,
    ),
    crypto.subtle.sign("HMAC", digestKey, plaintext),
  ]);
  return {
    aad,
    ciphertext: encodeBase64Url(ciphertext),
    digest: encodeBase64Url(digest),
    iv: encodeBase64Url(iv),
  };
}

export async function decryptPendingPayload(
  masterKey: string,
  context: PendingPayloadContext,
  encrypted: EncryptedPendingPayload,
): Promise<unknown> {
  const expectedAad = canonicalizeJson(pendingPayloadAad(context));
  if (encrypted.aad !== expectedAad) {
    throw new Error("pending_payload_context_mismatch");
  }
  const { aeadKey, digestKey } = await deriveKeys(masterKey, context.environment);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        additionalData: new TextEncoder().encode(encrypted.aad),
        iv: ownedBytes(decodeBase64Url(encrypted.iv)),
        name: "AES-GCM",
        tagLength: 128,
      },
      aeadKey,
      ownedBytes(decodeBase64Url(encrypted.ciphertext)),
    );
  } catch {
    throw new Error("pending_payload_decryption_failed");
  }
  const digestValid = await crypto.subtle.verify(
    "HMAC",
    digestKey,
    ownedBytes(decodeBase64Url(encrypted.digest)),
    plaintext,
  );
  if (!digestValid) throw new Error("pending_payload_digest_mismatch");
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new Error("pending_payload_invalid_json");
  }
}

function pendingPayloadAad(context: PendingPayloadContext) {
  return {
    action: context.action,
    environment: context.environment,
    expires_at: context.expiresAt,
    protocol: "pending-payload-aead-v1",
    request_id: context.requestId,
    requester_device_id: context.requesterDeviceId,
  };
}

async function deriveKeys(
  masterKey: string,
  environment: "dev" | "prod",
): Promise<{ aeadKey: CryptoKey; digestKey: CryptoKey }> {
  const raw = decodeBase64Url(masterKey);
  if (raw.byteLength !== 32) throw new Error("gateway_master_key_invalid");
  const baseKey = await crypto.subtle.importKey(
    "raw",
    ownedBytes(raw),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const salt = new TextEncoder().encode(`onenod:${environment}`);
  const [aeadKey, digestKey] = await Promise.all([
    crypto.subtle.deriveKey(
      {
        hash: "SHA-256",
        info: new TextEncoder().encode(AEAD_INFO),
        name: "HKDF",
        salt,
      },
      baseKey,
      { length: 256, name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    ),
    crypto.subtle.deriveKey(
      {
        hash: "SHA-256",
        info: new TextEncoder().encode(DIGEST_INFO),
        name: "HKDF",
        salt,
      },
      baseKey,
      { hash: "SHA-256", length: 256, name: "HMAC" },
      false,
      ["sign", "verify"],
    ),
  ]);
  return { aeadKey, digestKey };
}

function ownedBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}
