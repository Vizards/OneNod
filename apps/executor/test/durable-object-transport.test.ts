import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";

import { fetchExecutorDurableObject } from "../src/durable-object-transport.ts";
import { INTERNAL_ONEPASSWORD_PATHS } from "../src/internal-onepassword-api.ts";

const METADATA_PATH = "/internal/1password/item/metadata";
const READ_PATHS = [
  "/internal/health",
  "/internal/1password/catalog",
  "/internal/1password/secret/metadata",
  METADATA_PATH,
];

test("a transient reset gets a new stub and the same request body and headers", async (t) => {
  const logs = captureLogs(t);
  t.mock.method(Math, "random", () => 0);
  const original = request();
  const requests: Request[] = [];
  let stubs = 0;
  const expected = new Response('{"ok":true}', { status: 200 });
  const response = await fetchExecutorDurableObject(original, () => {
    stubs += 1;
    const stubNumber = stubs;
    let used = false;
    return {
      async fetch(incoming) {
        assert.equal(used, false, "a broken stub must never be reused");
        used = true;
        requests.push(incoming);
        assert.equal(await incoming.text(), '{"item_id":"private-item-canary"}');
        assert.equal(incoming.headers.get("authorization"), "Bearer test-secret-canary");
        assert.equal(incoming.method, "POST");
        if (stubNumber === 1) throw transientReset();
        return expected;
      },
    };
  });

  assert.equal(response, expected);
  assert.equal(stubs, 2);
  assert.notEqual(requests[0], requests[1]);
  assert.equal(original.bodyUsed, false);
  assert.deepEqual(logs.map((entry) => [entry.event, entry.attempt]), [
    ["executor_durable_object_failure", 1],
    ["executor_durable_object_response", 2],
  ]);
  assert.equal(logs[0]?.willRetry, true);
  const serialized = JSON.stringify(logs);
  for (const sensitive of ["private-item-canary", "test-secret-canary", "private-query", "private-error"]) {
    assert.equal(serialized.includes(sensitive), false);
  }
});

for (const path of READ_PATHS) {
  test(`${path} stops after three attempts with exponential backoff`, async (t) => {
    const logs = captureLogs(t);
    t.mock.timers.enable({ apis: ["setTimeout"] });
    t.mock.method(Math, "random", () => 0);
    let attempts = 0;
    const failure = transientReset();
    const result = fetchExecutorDurableObject(request(path), () => ({
      async fetch() {
        attempts += 1;
        throw failure;
      },
    }));
    const rejected = assert.rejects(result, (error) => error === failure);
    await settle();
    assert.equal(attempts, 1);
    t.mock.timers.tick(99);
    await settle();
    assert.equal(attempts, 1);
    t.mock.timers.tick(1);
    await settle();
    assert.equal(attempts, 2);
    t.mock.timers.tick(199);
    await settle();
    assert.equal(attempts, 2);
    t.mock.timers.tick(1);
    await rejected;
    assert.equal(attempts, 3);
    assert.deepEqual(logs.map((entry) => entry.willRetry), [true, true, false]);
  });
}

for (const path of [...INTERNAL_ONEPASSWORD_PATHS, `${METADATA_PATH}/`, "/unknown"]
  .filter((value) => !READ_PATHS.includes(value))) {
  test(`${path} is never replayed, even for retryable failures`, async () => {
    const original = request(path);
    let attempts = 0;
    const failure = transientReset();
    await assert.rejects(fetchExecutorDurableObject(original, () => ({
      async fetch(incoming) {
        attempts += 1;
        assert.equal(incoming, original);
        throw failure;
      },
    })), (error) => error === failure);
    assert.equal(attempts, 1);
  });
}

test("an unsupported method is not replayed", async () => {
  let attempts = 0;
  await assert.rejects(fetchExecutorDurableObject(
    new Request(`http://executor.internal${METADATA_PATH}`),
    () => ({ async fetch() { attempts += 1; throw transientReset(); } }),
  ));
  assert.equal(attempts, 1);
});

const terminalFailures = [
  new Error("Durable Object reset because its code was updated."),
  Object.assign(new Error("not transient"), { retryable: false }),
  Object.assign(new Error("not a boolean"), { retryable: "true" }),
  Object.assign(new Error("overloaded"), { retryable: true, overloaded: true }),
  Object.assign(new Error("cancelled"), { retryable: true, name: "AbortError" }),
  Object.assign(new Error("timed out"), { retryable: true, name: "TimeoutError" }),
];
for (const failure of terminalFailures) {
  test(`does not replay ${failure.message}`, async (t) => {
    const logs = captureLogs(t);
    let attempts = 0;
    await assert.rejects(fetchExecutorDurableObject(request(), () => ({
      async fetch() { attempts += 1; throw failure; },
    })), (error) => error === failure);
    assert.equal(attempts, 1);
    assert.equal(logs[0]?.willRetry, false);
  });
}

for (const status of [200, 400, 401, 403, 429, 500, 502, 503, 504]) {
  test(`HTTP ${status} responses pass through without retry`, async () => {
    let attempts = 0;
    const expected = new Response("original response", { status });
    const response = await fetchExecutorDurableObject(request(), () => ({
      async fetch() { attempts += 1; return expected; },
    }));
    assert.equal(response, expected);
    assert.equal(await response.text(), "original response");
    assert.equal(attempts, 1);
  });
}

test("all attempts share a deadline, including a hanging fetch", async (t) => {
  captureLogs(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.mock.method(Math, "random", () => 0);
  const first = deferred<Response>();
  const second = deferred<Response>();
  const signals: AbortSignal[] = [];
  const result = fetchExecutorDurableObject(request(), () => ({
    fetch(incoming) {
      signals.push(incoming.signal);
      return signals.length === 1 ? first.promise : second.promise;
    },
  }));
  const rejected = assert.rejects(result, { name: "TimeoutError" });
  await settle();
  t.mock.timers.tick(79_800);
  first.reject(transientReset());
  await settle();
  t.mock.timers.tick(100);
  await settle();
  assert.equal(signals.length, 2);
  assert.equal(signals[1]?.aborted, false);
  t.mock.timers.tick(100);
  await rejected;
  assert.equal(signals[1]?.aborted, true);
  second.resolve(new Response("late response"));
});

test("a deadline expiring during backoff prevents another dispatch", async (t) => {
  captureLogs(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const first = deferred<Response>();
  let attempts = 0;
  const result = fetchExecutorDurableObject(request(), () => ({
    fetch() { attempts += 1; return first.promise; },
  }));
  const rejected = assert.rejects(result, { name: "TimeoutError" });
  await settle();
  t.mock.timers.tick(79_999);
  first.reject(transientReset());
  await settle();
  t.mock.timers.tick(1);
  await rejected;
  assert.equal(attempts, 1);
});

for (const stage of ["before dispatch", "in flight", "during backoff"]) {
  test(`cancellation ${stage} prevents further attempts`, async (t) => {
    captureLogs(t);
    const controller = new AbortController();
    const pending = deferred<Response>();
    let attempts = 0;
    let incomingSignal: AbortSignal | undefined;
    if (stage === "before dispatch") controller.abort("private cancellation reason");
    const result = fetchExecutorDurableObject(request(METADATA_PATH, controller.signal), () => ({
      fetch(incoming) {
        attempts += 1;
        incomingSignal = incoming.signal;
        return stage === "during backoff" ? Promise.reject(transientReset()) : pending.promise;
      },
    }));
    const rejected = assert.rejects(result, {
      message: "executor request aborted",
      name: "AbortError",
    });
    await settle();
    controller.abort("private cancellation reason");
    await rejected;
    assert.equal(attempts, stage === "before dispatch" ? 0 : 1);
    if (incomingSignal) assert.equal(incomingSignal.aborted, true);
    pending.resolve(new Response("late response"));
  });
}

function request(path = METADATA_PATH, signal?: AbortSignal): Request {
  return new Request(`http://executor.internal${path}?context=private-query`, {
    body: '{"item_id":"private-item-canary"}',
    headers: { authorization: "Bearer test-secret-canary", "content-type": "application/json" },
    method: "POST",
    ...(signal === undefined ? {} : { signal }),
  });
}

function transientReset(): Error {
  return Object.assign(new Error("private-error"), { retryable: true });
}

function captureLogs(t: TestContext): Array<Record<string, unknown>> {
  const logs: Array<Record<string, unknown>> = [];
  const capture = (message: string): void => { logs.push(JSON.parse(message)); };
  t.mock.method(console, "log", capture);
  t.mock.method(console, "warn", capture);
  return logs;
}

function settle(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function deferred<T>(): {
  promise: Promise<T>;
  reject: (reason: unknown) => void;
  resolve: (value: T) => void;
} {
  let reject!: (reason: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail; });
  return { promise, reject, resolve };
}
