import {
  APPLICATION_ATTESTATION_HEADER,
  REQUESTER_HEADER_NAMES,
  buildRequesterCanonicalString,
  decodeBase64Url,
  formatApplicationAttestationString,
  requesterPublicKeyFingerprint,
  type RequesterSelfResponse,
  type VerifiedMacOSApplicationIdentityRequest,
} from "@onenod/protocol";

import { ownedBytes } from "../shared/owned-bytes.js";

// Authentication verifies signatures asynchronously. These writes therefore
// revalidate the authority row in the same SQLite statement that consumes the
// successful proof, closing revoke/verify races without a second await gap.
export const REVALIDATE_HUMAN_CREDENTIAL_SQL = `UPDATE human_credentials
  SET counter = ?, device_type = ?, backed_up = ?, last_used_at = ?
  WHERE id = ? AND counter = ? AND revoked_at IS NULL
  RETURNING id`;

export const STORE_ACTIVE_REQUESTER_NONCE_SQL = `INSERT INTO requester_nonces
  (device_id, nonce, expires_at)
  SELECT ?, ?, ?
  WHERE EXISTS (
    SELECT 1 FROM requesters
    WHERE device_id = ? AND revoked_at IS NULL
  )
  RETURNING nonce`;

export interface RequesterIdentity {
  canonicalString: string;
  deviceId: string;
  displayName: string;
  publicKey: string;
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

  const identity = {
    canonicalString: material.canonical_string,
    deviceId,
    displayName: requester.displayName,
    publicKey: requester.publicKey,
  };
  input.beforeUseNonce?.(identity);
  if (!input.useNonce(deviceId, nonce, Date.now() + 5 * 60_000)) {
    throw new RequesterAuthenticationError("request_replayed");
  }
  return identity;
}

/**
 * Proves that the signing identity is already an active requester without
 * consuming a replay nonce or mutating enrollment state. Replaying this
 * short-lived GET can reveal no more than the same public identity proof.
 */
export async function authenticateRequesterSelf(input: {
  audience: string;
  beforeUseNonce?: (identity: RequesterIdentity) => void;
  lookupRequester: (
    deviceId: string,
  ) => { displayName: string; publicKey: string } | undefined;
  request: Request;
}): Promise<RequesterSelfResponse> {
  const requester = await authenticateRequester({
    audience: input.audience,
    ...(input.beforeUseNonce
      ? { beforeUseNonce: input.beforeUseNonce }
      : {}),
    body: {},
    lookupRequester: input.lookupRequester,
    method: "GET",
    path: "/v1/requester-self",
    request: input.request,
    useNonce: () => true,
  });
  return {
    device_id: requester.deviceId,
    public_key_fingerprint: await requesterPublicKeyFingerprint(
      requester.publicKey,
    ),
    registered: true,
  };
}

export async function verifyApplicationAttestation(input: {
  identity: VerifiedMacOSApplicationIdentityRequest;
  request: Request;
  requester: RequesterIdentity;
}): Promise<boolean> {
  const encodedSignature = input.request.headers.get(
    APPLICATION_ATTESTATION_HEADER,
  );
  if (!encodedSignature) return false;

  let publicKeyBytes: Uint8Array<ArrayBuffer>;
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    publicKeyBytes = ownedBytes(decodeBase64Url(input.requester.publicKey));
    signatureBytes = ownedBytes(decodeBase64Url(encodedSignature));
  } catch {
    return false;
  }
  if (publicKeyBytes.byteLength !== 32 || signatureBytes.byteLength !== 64) {
    return false;
  }

  let material: string;
  try {
    material = formatApplicationAttestationString({
      principal_id: input.identity.principal_id,
      principal_scheme: input.identity.principal_scheme,
      requester_canonical_string: input.requester.canonicalString,
    });
  } catch {
    return false;
  }

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signatureBytes,
      new TextEncoder().encode(material),
    );
  } catch {
    return false;
  }
}
