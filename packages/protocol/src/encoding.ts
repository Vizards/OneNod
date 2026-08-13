import { base64urlnopad } from "@scure/base";

function asUint8Array(value: ArrayBuffer | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }

  return new Uint8Array(value);
}

export function encodeBase64Url(value: ArrayBuffer | Uint8Array): string {
  return base64urlnopad.encode(asUint8Array(value));
}

export function decodeBase64Url(value: string): Uint8Array {
  try {
    return base64urlnopad.decode(value);
  } catch {
    throw new TypeError("Expected canonical unpadded base64url.");
  }
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export async function sha256(value: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof value === "string" ? utf8(value) : value;
  const digestInput = new Uint8Array(bytes.byteLength);
  digestInput.set(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", digestInput);
  return new Uint8Array(digest);
}

export async function sha256Base64Url(value: string | Uint8Array): Promise<string> {
  return encodeBase64Url(await sha256(value));
}
