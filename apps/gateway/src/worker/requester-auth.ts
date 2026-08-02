import {
  REQUESTER_HEADER_NAMES,
  buildRequesterCanonicalString,
  decodeBase64Url,
} from "@onenod/protocol";

import { ownedBytes } from "../shared/owned-bytes.js";

export interface RequesterIdentity {
  deviceId: string;
  displayName: string;
}

export class RequesterAuthenticationError extends Error {
  override readonly name = "RequesterAuthenticationError";

  constructor(
    readonly code:
      | "request_replayed"
      | "request_signature_invalid"
      | "request_timestamp_invalid"
      | "requester_not_found",
  ) {
    super(code);
  }
}

export async function authenticateRequester(input: {
  audience: string;
  beforeUseNonce?: (identity: RequesterIdentity) => void;
  body: unknown;
  lookupRequester: (
    deviceId: string,
  ) => { displayName: string; publicKey: string } | undefined;
  method: string;
  path: string;
  request: Request;
  useNonce: (deviceId: string, nonce: string, expiresAt: number) => boolean;
}): Promise<RequesterIdentity> {
  const deviceId = input.request.headers.get(
    REQUESTER_HEADER_NAMES.deviceId,
  );
  const nonce = input.request.headers.get(REQUESTER_HEADER_NAMES.nonce);
  const signature = input.request.headers.get(
    REQUESTER_HEADER_NAMES.signature,
  );
  const rawTimestamp = input.request.headers.get(
    REQUESTER_HEADER_NAMES.timestamp,
  );
  if (
    !deviceId ||
    !nonce ||
    !signature ||
    !rawTimestamp ||
    deviceId.length > 128 ||
    nonce.length > 128
  ) {
    throw new RequesterAuthenticationError("request_signature_invalid");
  }

  const timestamp = Number(rawTimestamp);
  const nowSeconds = Math.floor(Date.now() / 1_000);
  if (
    !Number.isSafeInteger(timestamp) ||
    Math.abs(nowSeconds - timestamp) > 60
  ) {
    throw new RequesterAuthenticationError("request_timestamp_invalid");
  }

  const requester = input.lookupRequester(deviceId);
  if (!requester) {
    throw new RequesterAuthenticationError("requester_not_found");
  }

  let publicKeyBytes: Uint8Array<ArrayBuffer>;
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    publicKeyBytes = ownedBytes(decodeBase64Url(requester.publicKey));
    signatureBytes = ownedBytes(decodeBase64Url(signature));
  } catch {
    throw new RequesterAuthenticationError("request_signature_invalid");
  }
  if (publicKeyBytes.byteLength !== 32 || signatureBytes.byteLength !== 64) {
    throw new RequesterAuthenticationError("request_signature_invalid");
  }

  const material = await buildRequesterCanonicalString({
    audience: input.audience,
    body: input.body,
    device_id: deviceId,
    method: input.method,
    nonce,
    path: input.path,
    unix_seconds: timestamp,
  });

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "Ed25519",
      key,
      signatureBytes,
      new TextEncoder().encode(material.canonical_string),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new RequesterAuthenticationError("request_signature_invalid");
  }

  const identity = { deviceId, displayName: requester.displayName };
  input.beforeUseNonce?.(identity);
  if (!input.useNonce(deviceId, nonce, Date.now() + 5 * 60_000)) {
    throw new RequesterAuthenticationError("request_replayed");
  }
  return identity;
}
