import assert from "node:assert/strict";
import test from "node:test";

import { encodeBase64Url } from "@onenod/protocol";

import {
  deriveRequestPollingToken,
  pollingTokensMatch,
  readRequestPollingBearer,
} from "../src/worker/request-polling.js";

const masterKey = encodeBase64Url(Uint8Array.from({ length: 32 }, (_, index) => index));

test("polling capabilities are deterministic and domain separated", async () => {
  const base = {
    deviceId: "requester-a",
    masterKey,
    origin: "https://gateway.example",
    requestId: "request-a",
  };
  const first = await deriveRequestPollingToken(base);

  assert.match(first, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(await deriveRequestPollingToken(base), first);
  assert.notEqual(
    await deriveRequestPollingToken({ ...base, requestId: "request-b" }),
    first,
  );
  assert.notEqual(
    await deriveRequestPollingToken({ ...base, deviceId: "requester-b" }),
    first,
  );
  assert.notEqual(
    await deriveRequestPollingToken({ ...base, origin: "https://other.example" }),
    first,
  );
});

test("accepts only an exact bearer capability", async () => {
  const token = await deriveRequestPollingToken({
    deviceId: "requester-a",
    masterKey,
    origin: "https://gateway.example",
    requestId: "request-a",
  });
  const request = new Request("https://gateway.example/v1/requests/request-a/status", {
    headers: { authorization: `Bearer ${token}` },
  });

  assert.equal(readRequestPollingBearer(request), token);
  assert.equal(pollingTokensMatch(token, token), true);
  assert.equal(pollingTokensMatch(`${token.slice(0, -1)}A`, token), false);
  assert.equal(
    readRequestPollingBearer(
      new Request(request.url, { headers: { authorization: `bearer ${token}` } }),
    ),
    undefined,
  );
});

test("rejects malformed master keys", async () => {
  await assert.rejects(
    deriveRequestPollingToken({
      deviceId: "requester-a",
      masterKey: "short",
      origin: "https://gateway.example",
      requestId: "request-a",
    }),
    /gateway_master_key_invalid/u,
  );
});
