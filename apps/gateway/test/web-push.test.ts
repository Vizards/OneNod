import assert from "node:assert/strict";
import test from "node:test";

import {
  deliverWebPush,
  validatePushSubscription,
  workerSafePushHeaders,
} from "../src/worker/web-push.js";

test("validates and normalizes an HTTPS push subscription", () => {
  const value = validatePushSubscription({
    endpoint: "https://example.push.apple.com/QWxhZGRpbjpvcGVuIHNlc2FtZQ",
    expirationTime: null,
    keys: {
      auth: "A".repeat(22),
      p256dh: "B".repeat(87),
    },
  });
  assert.equal(value.endpoint, "https://example.push.apple.com/QWxhZGRpbjpvcGVuIHNlc2FtZQ");
  assert.equal(value.expirationTime, null);
});

test("rejects local, insecure, and credential-bearing push endpoints", () => {
  for (const endpoint of [
    "http://push.example.com/value",
    "https://localhost/value",
    "https://127.0.0.1/value",
    "https://user:password@push.example.com/value",
  ]) {
    assert.throws(
      () =>
        validatePushSubscription({
          endpoint,
          expirationTime: null,
          keys: { auth: "A".repeat(22), p256dh: "B".repeat(87) },
        }),
      /push_endpoint_invalid/u,
    );
  }
});

test("rejects malformed push subscription keys", () => {
  assert.throws(
    () =>
      validatePushSubscription({
        endpoint: "https://push.example.com/value",
        expirationTime: null,
        keys: { auth: "not standard base64+", p256dh: "short" },
      }),
    /push_keys_invalid/u,
  );
});

test("drops upstream Content-Length while preserving Web Push headers", () => {
  const headers = workerSafePushHeaders({
    authorization: "WebPush signed-token",
    "content-encoding": "aesgcm",
    "content-length": "123",
    "crypto-key": "dh=ephemeral;p256ecdsa=vapid",
    encryption: "salt=value",
    ttl: "120",
  });

  assert.equal(headers.has("content-length"), false);
  assert.equal(headers.get("content-encoding"), "aesgcm");
  assert.equal(headers.get("crypto-key"), "dh=ephemeral;p256ecdsa=vapid");
  assert.equal(headers.get("authorization"), "WebPush signed-token");
});

test("builds a decryptable Web Push request without an external runtime", async () => {
  const clientKeys = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const clientPublic = new Uint8Array(
    await crypto.subtle.exportKey("raw", clientKeys.publicKey),
  );
  const authSecret = crypto.getRandomValues(new Uint8Array(16));
  const vapidKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const vapidPublic = new Uint8Array(
    await crypto.subtle.exportKey("raw", vapidKeys.publicKey),
  );
  const vapidPrivate = await crypto.subtle.exportKey("jwk", vapidKeys.privateKey);
  assert.equal(typeof vapidPrivate.d, "string");

  const message = {
    body: "Approve this request",
    requestId: "request-test",
    tag: "approval-test",
    title: "Approval requested",
    url: "https://gateway.example/requests/request-test",
  };
  let calls = 0;
  const result = await deliverWebPush(
    {
      auth: encodeBase64Url(authSecret),
      endpoint: "https://push.example.test/delivery-token",
      expirationTime: null,
      p256dh: encodeBase64Url(clientPublic),
    },
    message,
    {
      privateKey: vapidPrivate.d,
      publicKey: encodeBase64Url(vapidPublic),
      subject: "mailto:operator@example.test",
    },
    (async (input: RequestInfo | URL) => {
      calls += 1;
      const request = input instanceof Request ? input : new Request(input);
      assert.equal(request.method, "POST");
      assert.equal(request.headers.has("content-length"), false);
      assert.equal(request.headers.get("content-encoding"), "aesgcm");
      assert.equal(request.headers.get("ttl"), "120");
      assert.equal(request.headers.get("urgency"), "high");
      assert.equal(request.headers.get("topic"), "approval-test");

      const authorization = request.headers.get("authorization") ?? "";
      const vapid = /^vapid t=([^,]+), k=(.+)$/u.exec(authorization);
      assert.ok(vapid);
      assert.equal(vapid[2], encodeBase64Url(vapidPublic));
      const jwt = vapid[1]!;
      const [encodedHeader, encodedPayload, encodedSignature] = jwt.split(".");
      assert.equal(
        await crypto.subtle.verify(
          { hash: "SHA-256", name: "ECDSA" },
          vapidKeys.publicKey,
          decodeBase64Url(encodedSignature!),
          new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
        ),
        true,
      );
      const claims = JSON.parse(
        new TextDecoder().decode(decodeBase64Url(encodedPayload!)),
      ) as Record<string, unknown>;
      assert.equal(claims.aud, "https://push.example.test");
      assert.equal(claims.sub, "mailto:operator@example.test");

      const localPublic = headerParameter(request.headers.get("crypto-key"), "dh");
      const salt = headerParameter(request.headers.get("encryption"), "salt");
      const plaintext = await decryptPushPayload(
        new Uint8Array(await request.arrayBuffer()),
        clientKeys.privateKey,
        clientPublic,
        authSecret,
        decodeBase64Url(localPublic),
        decodeBase64Url(salt),
      );
      assert.deepEqual(JSON.parse(new TextDecoder().decode(plaintext)), {
        body: message.body,
        requestId: message.requestId,
        tag: message.tag,
        title: message.title,
        url: message.url,
      });
      return new Response(null, { status: 201 });
    }) as typeof fetch,
  );

  assert.deepEqual(result, { outcome: "delivered", status: 201 });
  assert.equal(calls, 1);
});

async function decryptPushPayload(
  ciphertext: Uint8Array<ArrayBuffer>,
  clientPrivateKey: CryptoKey,
  clientPublicKey: Uint8Array<ArrayBuffer>,
  authSecret: Uint8Array<ArrayBuffer>,
  localPublicKey: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const importedLocalPublicKey = await crypto.subtle.importKey(
    "raw",
    localPublicKey,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: importedLocalPublicKey },
      clientPrivateKey,
      256,
    ),
  );
  const inputKeyMaterial = await hkdfExpand(
    authSecret,
    sharedSecret,
    text("Content-Encoding: auth\0"),
    32,
  );
  const contentEncryptionKey = await hkdfExpand(
    salt,
    inputKeyMaterial,
    contextInfo("aesgcm", clientPublicKey, localPublicKey),
    16,
  );
  const nonce = await hkdfExpand(
    salt,
    inputKeyMaterial,
    contextInfo("nonce", clientPublicKey, localPublicKey),
    12,
  );
  const key = await crypto.subtle.importKey(
    "raw",
    contentEncryptionKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const padded = new Uint8Array(
    await crypto.subtle.decrypt({ iv: nonce, name: "AES-GCM" }, key, ciphertext),
  );
  const paddingLength = (padded[0]! << 8) | padded[1]!;
  return padded.slice(2 + paddingLength);
}

async function hkdfExpand(
  salt: Uint8Array<ArrayBuffer>,
  inputKeyMaterial: Uint8Array<ArrayBuffer>,
  information: Uint8Array<ArrayBuffer>,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const pseudoRandomKey = await hmac(salt, inputKeyMaterial);
  const output = await hmac(
    pseudoRandomKey,
    concatenate(information, new Uint8Array([1])),
  );
  return output.slice(0, length);
}

async function hmac(
  keyBytes: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

function contextInfo(
  label: string,
  clientPublicKey: Uint8Array<ArrayBuffer>,
  localPublicKey: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  return concatenate(
    text(`Content-Encoding: ${label}\0P-256\0`),
    new Uint8Array([0, clientPublicKey.byteLength]),
    clientPublicKey,
    new Uint8Array([0, localPublicKey.byteLength]),
    localPublicKey,
  );
}

function concatenate(...arrays: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(
    arrays.reduce((total, current) => total + current.byteLength, 0),
  );
  let offset = 0;
  for (const current of arrays) {
    result.set(current, offset);
    offset += current.byteLength;
  }
  return result;
}

function text(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value);
}

function headerParameter(value: string | null, name: string): string {
  for (const parameter of value?.split(";") ?? []) {
    const [candidate, fieldValue] = parameter.split("=", 2);
    if (candidate === name && fieldValue) return fieldValue;
  }
  assert.fail(`missing ${name} header parameter`);
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function encodeBase64Url(value: Uint8Array<ArrayBuffer>): string {
  return Buffer.from(value).toString("base64url");
}
