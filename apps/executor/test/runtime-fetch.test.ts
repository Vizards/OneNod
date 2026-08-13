import assert from "node:assert/strict";
import test from "node:test";

import type { ActivePluginLease } from "../src/reusable-extism-runtime.ts";
import { createRestrictedFetch } from "../src/runtime.ts";

test("restricted fetch rejects disallowed hosts before network access", async () => {
  let calls = 0;
  const lease = activeLease();
  const restricted = createRestrictedFetch(
    "my.1password.com",
    1,
    () => lease,
    (async () => {
      calls += 1;
      return new Response("unexpected");
    }) as typeof fetch,
  );

  await assert.rejects(restricted("https://example.com"), /upstream_host_not_allowed/);
  assert.equal(calls, 0);
});

test("restricted fetch reads the active lease deadline on every request", async () => {
  const originalNow = Date.now;
  let now = 1_000;
  Date.now = () => now;
  let calls = 0;
  let redirect: RequestRedirect | undefined;
  let lease: ActivePluginLease | undefined = activeLease(1_100);
  try {
    const restricted = createRestrictedFetch(
      "my.1password.com",
      1,
      () => lease,
      (async (_input, init) => {
        calls += 1;
        redirect = init?.redirect;
        return new Response("ok");
      }) as typeof fetch,
    );
    await restricted("https://events.1password.com");
    assert.equal(redirect, "manual");

    now = 1_101;
    await assert.rejects(restricted("https://events.1password.com"), {
      name: "TimeoutError",
    });
    lease = activeLease(1_500);
    await restricted("https://events.1password.com");
    assert.equal(calls, 2);
  } finally {
    Date.now = originalNow;
  }
});

test("restricted fetch fails closed outside its lease and on generation mismatch", async () => {
  let calls = 0;
  let lease: ActivePluginLease | undefined;
  const restricted = createRestrictedFetch(
    "my.1password.com",
    7,
    () => lease,
    (async () => {
      calls += 1;
      return new Response("unexpected");
    }) as typeof fetch,
  );

  await assert.rejects(
    restricted("https://events.1password.com"),
    /plugin_fetch_outside_active_lease/,
  );
  lease = activeLease(Date.now() + 10_000, 8);
  await assert.rejects(
    restricted("https://events.1password.com"),
    /plugin_fetch_lease_mismatch/,
  );
  assert.equal(calls, 0);
});

test("restricted fetch refuses a pre-aborted source signal before network access", async () => {
  let calls = 0;
  const controller = new AbortController();
  controller.abort("caller_aborted");
  const lease = activeLease();
  const restricted = createRestrictedFetch(
    "my.1password.com",
    1,
    () => lease,
    (async () => {
      calls += 1;
      return new Response("unexpected");
    }) as typeof fetch,
  );

  await assert.rejects(
    restricted("https://events.1password.com", { signal: controller.signal }),
  );
  assert.equal(calls, 0);
});

test("restricted fetch keeps deadline enforcement active while buffering the body", async () => {
  const leaseController = new AbortController();
  let bodyCancelled = false;
  const lease: ActivePluginLease = {
    aborted: false,
    deadlineAt: Date.now() + 10_000,
    generation: 1,
    signal: leaseController.signal,
    upstreamRateLimited: false,
  };
  const responseStarted = deferred<void>();
  const restricted = createRestrictedFetch(
    "my.1password.com",
    1,
    () => lease,
    (async () => {
      responseStarted.resolve();
      return new Response(
        new ReadableStream<Uint8Array>({
          cancel() {
            bodyCancelled = true;
          },
          pull() {
            return new Promise<void>(() => {});
          },
        }),
      );
    }) as typeof fetch,
  );

  const request = restricted("https://events.1password.com");
  await responseStarted.promise;
  await Promise.resolve();
  const reason = new DOMException("operation deadline exceeded", "TimeoutError");
  lease.aborted = true;
  leaseController.abort(reason);

  await assert.rejects(request, { name: "TimeoutError" });
  assert.equal(bodyCancelled, true);
});

test("restricted fetch records a 1Password rate-limit response on the active lease", async () => {
  const lease = activeLease();
  let upstreamRequests = 0;
  lease.observeUpstreamRequest = () => {
    upstreamRequests += 1;
  };
  const restricted = createRestrictedFetch(
    "my.1password.com",
    1,
    () => lease,
    (async () => new Response("limited", { status: 429 })) as typeof fetch,
  );

  const response = await restricted("https://events.1password.com");
  assert.equal(response.status, 429);
  assert.equal(lease.upstreamRateLimited, true);
  assert.equal(upstreamRequests, 1);
});

function activeLease(
  deadlineAt = Date.now() + 10_000,
  generation = 1,
): ActivePluginLease {
  return {
    aborted: false,
    deadlineAt,
    generation,
    signal: new AbortController().signal,
    upstreamRateLimited: false,
  };
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
