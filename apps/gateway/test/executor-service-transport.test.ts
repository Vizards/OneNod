import assert from "node:assert/strict";
import test from "node:test";

import {
  EXECUTOR_PROTOCOL_HEADER,
  EXECUTOR_PROTOCOL_VERSION,
} from "@onenod/protocol";

import {
  callExecutorService,
  EXECUTOR_BODY_DIGEST_HEADER,
  EXECUTOR_REQUEST_ID_HEADER,
  type ExecutorServiceBinding,
} from "../src/worker/executor-service-transport.js";
import { ExecutorTransportError } from "../src/worker/executor-transport.js";

function protocolResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "content-type": "application/json",
      [EXECUTOR_PROTOCOL_HEADER]: EXECUTOR_PROTOCOL_VERSION,
    },
    status,
  });
}

test("calls a bound executor with the existing bearer and internal request shape", async () => {
  let captured: Request | undefined;
  const service: ExecutorServiceBinding = {
    async fetch(request) {
      captured = request;
      return protocolResponse({ items: [], ok: true });
    },
  };

  const trusted = await callExecutorService({
    authToken: "dummy-executor-auth-token",
    body: { query: "dummy" },
    path: "/internal/1password/catalog",
    service,
    timeoutMs: 100,
  });

  assert.ok(captured);
  assert.equal(
    captured.url,
    "http://executor.internal/internal/1password/catalog",
  );
  assert.equal(captured.method, "POST");
  assert.equal(
    captured.headers.get("authorization"),
    "Bearer dummy-executor-auth-token",
  );
  assert.equal(captured.headers.get("content-type"), "application/json");
  assert.deepEqual(await captured.json(), { query: "dummy" });
  assert.deepEqual(trusted, {
    body: { items: [], ok: true },
    status: 200,
  });
});

test("binds a mutation to a closed request ID and canonical body digest", async () => {
  let captured: Request | undefined;
  const service: ExecutorServiceBinding = {
    async fetch(request) {
      captured = request;
      return protocolResponse({ item_id: "dummy-item", ok: true, version: 1 });
    },
  };

  await callExecutorService({
    authToken: "dummy-executor-auth-token",
    body: { action: "item.create" },
    execution: {
      bodyDigest: "a".repeat(43),
      requestId: "request-0001",
    },
    path: "/internal/1password/item/mutate",
    service,
    timeoutMs: 100,
  });

  assert.ok(captured);
  assert.equal(captured.headers.get(EXECUTOR_REQUEST_ID_HEADER), "request-0001");
  assert.equal(captured.headers.get(EXECUTOR_BODY_DIGEST_HEADER), "a".repeat(43));
});

test("rejects malformed execution identity before calling the binding", async () => {
  let called = false;
  const service: ExecutorServiceBinding = {
    async fetch() {
      called = true;
      return protocolResponse({ ok: true });
    },
  };

  await assert.rejects(
    callExecutorService({
      authToken: "dummy-executor-auth-token",
      body: { action: "item.archive" },
      execution: { bodyDigest: "not-a-digest", requestId: "bad/request" },
      path: "/internal/1password/item/mutate",
      service,
      timeoutMs: 100,
    }),
    TypeError,
  );
  assert.equal(called, false);
});

test("wraps a rejected service binding fetch as a stable unavailable error", async () => {
  const canary = "service_binding_failure_canary";
  const service: ExecutorServiceBinding = {
    async fetch() {
      throw new Error(canary);
    },
  };

  await assert.rejects(
    callExecutorService({
      authToken: "dummy-executor-auth-token",
      body: {},
      path: "/internal/1password/catalog",
      service,
      timeoutMs: 100,
    }),
    (error: unknown) => {
      assert.ok(error instanceof ExecutorTransportError);
      assert.equal(error.failure, "unavailable");
      assert.doesNotMatch(JSON.stringify(error), new RegExp(canary));
      return true;
    },
  );
});

test("applies the existing bounded trusted-response reader to service bindings", async () => {
  const service: ExecutorServiceBinding = {
    async fetch() {
      return new Response(new Uint8Array(64 * 1024 + 1), {
        headers: {
          "content-type": "application/json",
          [EXECUTOR_PROTOCOL_HEADER]: EXECUTOR_PROTOCOL_VERSION,
        },
      });
    },
  };

  await assert.rejects(
    callExecutorService({
      authToken: "dummy-executor-auth-token",
      body: {},
      path: "/internal/1password/catalog",
      service,
      timeoutMs: 100,
    }),
    (error: unknown) => {
      assert.ok(error instanceof ExecutorTransportError);
      assert.equal(error.failure, "untrusted_response");
      return true;
    },
  );
});

test("rejects an executor response with the retired protocol version", async () => {
  const service: ExecutorServiceBinding = {
    async fetch() {
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json",
          [EXECUTOR_PROTOCOL_HEADER]: "phase0-v1",
        },
      });
    },
  };

  await assert.rejects(
    callExecutorService({
      authToken: "dummy-executor-auth-token",
      body: {},
      path: "/internal/health",
      service,
      timeoutMs: 100,
    }),
    (error: unknown) => {
      assert.ok(error instanceof ExecutorTransportError);
      assert.equal(error.failure, "untrusted_response");
      return true;
    },
  );
});

test("rejects paths that could escape the fixed internal service origin", async () => {
  let called = false;
  const service: ExecutorServiceBinding = {
    async fetch() {
      called = true;
      return protocolResponse({ ok: true });
    },
  };

  await assert.rejects(
    callExecutorService({
      authToken: "dummy-executor-auth-token",
      body: {},
      path: "//unexpected.example/internal",
      service,
      timeoutMs: 100,
    }),
    TypeError,
  );
  assert.equal(called, false);
});
