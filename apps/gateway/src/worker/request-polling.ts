import { decodeBase64Url, encodeBase64Url } from "@onenod/protocol";

const POLLING_TOKEN_CONTEXT = "onenod-request-poll-v1";
const POLLING_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export async function deriveRequestPollingToken(input: {
  deviceId: string;
  masterKey: string;
  origin: string;
  requestId: string;
}): Promise<string> {
  let masterKey: Uint8Array;
  try {
    masterKey = decodeBase64Url(input.masterKey);
  } catch {
    throw new TypeError("gateway_master_key_invalid");
  }
  if (masterKey.byteLength !== 32) {
    throw new TypeError("gateway_master_key_invalid");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    ownedBytes(masterKey),
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  const material = JSON.stringify([
    POLLING_TOKEN_CONTEXT,
    new URL(input.origin).host,
    input.requestId,
    input.deviceId,
  ]);
  return encodeBase64Url(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(material)),
    ),
  );
}

export function readRequestPollingBearer(request: Request): string | undefined {
  const authorization = request.headers.get("authorization");
  if (!authorization) return undefined;
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/u.exec(authorization);
  return match?.[1];
}

export function pollingTokensMatch(
  actual: string | undefined,
  expected: string,
): boolean {
  if (!actual || !POLLING_TOKEN_PATTERN.test(actual)) return false;
  const left = new TextEncoder().encode(actual);
  const right = new TextEncoder().encode(expected);
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function ownedBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}
