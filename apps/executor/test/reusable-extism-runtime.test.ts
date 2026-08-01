import assert from "node:assert/strict";
import test from "node:test";

import {
  type CachedExtismPlugin,
  type CachedPluginFactory,
  ReusableExtismRuntime,
  ReusableExtismRuntimeError,
} from "../src/reusable-extism-runtime.ts";

const ACCOUNT_HOST = "my.1password.com";
const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

test("50 concurrent leases share one plugin and execute strictly serially", async () => {
  let factoryCalls = 0;
  let activeOperations = 0;
  let maximumActiveOperations = 0;
  const entryOrder: number[] = [];
  const plugin = fakePlugin();
  const runtime = new ReusableExtismRuntime(async () => {
    factoryCalls += 1;
    await Promise.resolve();
    return plugin;
  });

  const outcomes = await Promise.all(
    Array.from({ length: 50 }, (_, index) =>
      runtime.withLease(
        leaseOptions(),
        async () => {
          activeOperations += 1;
          maximumActiveOperations = Math.max(
            maximumActiveOperations,
            activeOperations,
          );
          entryOrder.push(index);
          await new Promise<void>((resolve) => setImmediate(resolve));
          activeOperations -= 1;
          return index;
        },
      ),
    ),
  );

  assert.equal(factoryCalls, 1);
  assert.equal(maximumActiveOperations, 1);
  assert.deepEqual(entryOrder, Array.from({ length: 50 }, (_, index) => index));
  assert.deepEqual(
    outcomes.map(({ pluginCreated, pluginReused, value }) => ({
      pluginCreated,
      pluginReused,
      value,
    })),
    Array.from({ length: 50 }, (_, index) => ({
      pluginCreated: index === 0,
      pluginReused: index !== 0,
      value: index,
    })),
  );
  assert.ok(outcomes.every(({ pluginDisposition }) => pluginDisposition === "retained"));
  assert.ok(
    outcomes.every(
      ({ guestPagesAfter, guestPagesBefore }) =>
        guestPagesBefore === 1 && guestPagesAfter === 1,
    ),
  );
});

test("queued aborted and expired leases never enter the plugin operation", async () => {
  const holderStarted = deferred<void>();
  const releaseHolder = deferred<void>();
  const runtime = new ReusableExtismRuntime(async () => fakePlugin());
  const holder = runtime.withLease(leaseOptions(), async () => {
    holderStarted.resolve();
    await releaseHolder.promise;
  });
  await holderStarted.promise;

  let abortedEntries = 0;
  const abortController = new AbortController();
  const aborted = runtime.withLease(
    { ...leaseOptions(), signal: abortController.signal },
    async () => {
      abortedEntries += 1;
    },
  );
  abortController.abort(new DOMException("test cancellation", "AbortError"));

  let expiredEntries = 0;
  const expired = runtime.withLease(
    { accountHost: ACCOUNT_HOST, deadlineAt: Date.now() + 20 },
    async () => {
      expiredEntries += 1;
    },
  );

  try {
    await assert.rejects(aborted, /operation_aborted/);
    await assert.rejects(expired, /operation_deadline_exceeded/);
    assert.equal(abortedEntries, 0);
    assert.equal(expiredEntries, 0);
  } finally {
    releaseHolder.resolve();
    await holder;
  }

  const followup = await runtime.withLease(leaseOptions(), async () => "entered");
  assert.equal(followup.value, "entered");
  assert.equal(followup.pluginReused, true);
});

test("a poisoned lease evicts its plugin and the next lease rebuilds", async () => {
  const plugins: FakePlugin[] = [];
  const runtime = new ReusableExtismRuntime(async () => {
    const plugin = fakePlugin();
    plugins.push(plugin);
    return plugin;
  });

  const poisoned = await runtime.withLease(leaseOptions(), async (lease) => {
    lease.poison();
    return "completed_but_not_reusable";
  });
  const rebuilt = await runtime.withLease(leaseOptions(), async () => "fresh");

  assert.equal(poisoned.value, "completed_but_not_reusable");
  assert.equal(poisoned.guestPagesBefore, 1);
  assert.equal(poisoned.guestPagesAfter, 1);
  assert.equal(poisoned.pluginDisposition, "evicted");
  assert.equal(plugins[0]?.closeCalls, 1);
  assert.equal(plugins.length, 2);
  assert.equal(rebuilt.pluginCreated, true);
  assert.equal(rebuilt.pluginReused, false);
  assert.equal(rebuilt.pluginDisposition, "retained");
});

test("account host and credential digest identity changes close before replacement", async () => {
  const events: string[] = [];
  let factoryCalls = 0;
  const factory: CachedPluginFactory = async (accountHost, generation) => {
    factoryCalls += 1;
    const label = `${accountHost}:${generation}`;
    events.push(`create:${label}`);
    return fakePlugin({
      close: async () => {
        events.push(`close:${label}`);
      },
    });
  };
  const runtime = new ReusableExtismRuntime(factory);

  const initial = await runtime.withLease(
    leaseOptions({ credentialDigest: DIGEST_A }),
    async () => "initial",
  );
  const sameIdentity = await runtime.withLease(
    leaseOptions({
      accountHost: "HTTPS://MY.1PASSWORD.COM",
      credentialDigest: DIGEST_A,
    }),
    async () => "same",
  );
  const newDigest = await runtime.withLease(
    leaseOptions({ credentialDigest: DIGEST_B }),
    async () => "new_digest",
  );
  const newHost = await runtime.withLease(
    leaseOptions({ accountHost: "my.1password.eu", credentialDigest: DIGEST_B }),
    async () => "new_host",
  );

  assert.equal(initial.pluginCreated, true);
  assert.equal(sameIdentity.pluginReused, true);
  assert.equal(newDigest.pluginCreated, true);
  assert.equal(newDigest.pluginReused, false);
  assert.equal(newHost.pluginCreated, true);
  assert.equal(newHost.pluginReused, false);
  assert.equal(factoryCalls, 3);
  assert.deepEqual(events, [
    "create:my.1password.com:1",
    "close:my.1password.com:1",
    "create:my.1password.com:2",
    "close:my.1password.com:2",
    "create:my.1password.eu:3",
  ]);
});

test("a close failure still drops the poisoned plugin and never reuses it", async () => {
  const plugins: FakePlugin[] = [];
  const runtime = new ReusableExtismRuntime(async () => {
    const plugin = fakePlugin(
      plugins.length === 0
        ? {
            close: async () => {
              throw new Error("simulated close failure");
            },
          }
        : {},
    );
    plugins.push(plugin);
    return plugin;
  });

  const first = await runtime.withLease(leaseOptions(), async (lease) => {
    lease.poison();
  });
  const second = await runtime.withLease(leaseOptions(), async () => "replacement");

  assert.equal(first.pluginDisposition, "evict_failed");
  assert.equal(first.guestPagesBefore, 1);
  assert.equal(first.guestPagesAfter, 1);
  assert.equal(plugins[0]?.closeCalls, 1);
  assert.equal(plugins.length, 2);
  assert.equal(second.pluginCreated, true);
  assert.equal(second.pluginReused, false);
  assert.equal(second.value, "replacement");
});

test("maximum uses rotates only after the configured successful lease count", async () => {
  const plugins: FakePlugin[] = [];
  const runtime = new ReusableExtismRuntime(
    async () => {
      const plugin = fakePlugin();
      plugins.push(plugin);
      return plugin;
    },
    { maximumUses: 2 },
  );

  const first = await runtime.withLease(leaseOptions(), async () => 1);
  const second = await runtime.withLease(leaseOptions(), async () => 2);
  const third = await runtime.withLease(leaseOptions(), async () => 3);

  assert.deepEqual(
    [first, second, third].map(
      ({ pluginCreated, pluginDisposition, pluginReused }) => ({
        pluginCreated,
        pluginDisposition,
        pluginReused,
      }),
    ),
    [
      {
        pluginCreated: true,
        pluginDisposition: "retained",
        pluginReused: false,
      },
      {
        pluginCreated: false,
        pluginDisposition: "evicted",
        pluginReused: true,
      },
      {
        pluginCreated: true,
        pluginDisposition: "retained",
        pluginReused: false,
      },
    ],
  );
  assert.equal(plugins.length, 2);
  assert.equal(plugins[0]?.closeCalls, 1);
});

test("guest memory over the page limit is wiped, evicted, and rebuilt", async () => {
  const oversizedMemory = new WebAssembly.Memory({ initial: 2 });
  new Uint8Array(oversizedMemory.buffer).fill(0x5a);
  const plugins: FakePlugin[] = [];
  const runtime = new ReusableExtismRuntime(
    async () => {
      const plugin = fakePlugin({
        memory: plugins.length === 0 ? oversizedMemory : new WebAssembly.Memory({ initial: 1 }),
      });
      plugins.push(plugin);
      return plugin;
    },
    { maximumGuestPages: 1 },
  );

  const oversized = await runtime.withLease(leaseOptions(), async () => "oversized");
  const rebuilt = await runtime.withLease(leaseOptions(), async () => "within_limit");

  assert.equal(oversized.pluginDisposition, "evicted");
  assert.equal(oversized.guestPagesBefore, 2);
  assert.equal(oversized.guestPagesAfter, 2);
  assert.equal(plugins[0]?.closeCalls, 1);
  assert.ok(new Uint8Array(oversizedMemory.buffer).every((byte) => byte === 0));
  assert.equal(plugins.length, 2);
  assert.equal(rebuilt.pluginCreated, true);
  assert.equal(rebuilt.pluginReused, false);
  assert.equal(rebuilt.pluginDisposition, "retained");
});

test("guest page telemetry captures growth without exposing guest memory", async () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const runtime = new ReusableExtismRuntime(async () => fakePlugin({ memory }));

  const outcome = await runtime.withLease(leaseOptions(), async () => {
    memory.grow(2);
    return "grown";
  });

  assert.deepEqual(
    {
      guestPagesAfter: outcome.guestPagesAfter,
      guestPagesBefore: outcome.guestPagesBefore,
      value: outcome.value,
    },
    { guestPagesAfter: 3, guestPagesBefore: 1, value: "grown" },
  );
});

test("operation failures retain numeric guest page telemetry on the safe error", async () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const runtime = new ReusableExtismRuntime(async () => fakePlugin({ memory }));

  await assert.rejects(
    runtime.withLease(leaseOptions(), async () => {
      memory.grow(1);
      throw new Error("raw operation failure");
    }),
    (error) => {
      assert.ok(error instanceof ReusableExtismRuntimeError);
      assert.equal(error.guestPagesBefore, 1);
      assert.equal(error.guestPagesAfter, 2);
      assert.equal(error.pluginDisposition, "evicted");
      return true;
    },
  );
});

interface FakePlugin extends CachedExtismPlugin {
  closeCalls: number;
}

interface FakePluginOptions {
  close?: () => Promise<void>;
  memory?: WebAssembly.Memory;
}

function fakePlugin(options: FakePluginOptions = {}): FakePlugin {
  const memory = options.memory ?? new WebAssembly.Memory({ initial: 1 });
  const plugin = {
    call: async () => ({ bytes: () => new Uint8Array() }),
    close: async () => {
      plugin.closeCalls += 1;
      await options.close?.();
    },
    closeCalls: 0,
    getExports: async () => [],
    getImports: async () => [],
    getInstance: async () => ({ exports: { memory } }),
    isActive: () => false,
  };
  return plugin as unknown as FakePlugin;
}

function leaseOptions(
  overrides: Partial<{
    accountHost: string;
    credentialDigest: string;
    deadlineAt: number;
  }> = {},
): {
  accountHost: string;
  credentialDigest?: string;
  deadlineAt: number;
} {
  return {
    accountHost: overrides.accountHost ?? ACCOUNT_HOST,
    deadlineAt: overrides.deadlineAt ?? Date.now() + 5_000,
    ...(overrides.credentialDigest === undefined
      ? {}
      : { credentialDigest: overrides.credentialDigest }),
  };
}

function deferred<T>(): {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T | PromiseLike<T>) => void;
} {
  let reject!: (reason?: unknown) => void;
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, reject, resolve };
}
