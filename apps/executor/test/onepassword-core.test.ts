import assert from "node:assert/strict";
import test from "node:test";

import {
  CoreAdapterError,
  runWithOnePasswordClient,
} from "../src/onepassword-core.ts";
import {
  type CachedExtismPlugin,
  ReusableExtismRuntime,
} from "../src/reusable-extism-runtime.ts";

const encoder = new TextEncoder();
const fakeServiceAccountToken = `ops_${"c".repeat(64)}`;
const runOptions = {
  accountHost: "my.1password.com",
  deadlineAt: Date.now() + 60_000,
  serviceAccountToken: fakeServiceAccountToken,
};

test("core reuses the plugin but initializes and releases a fresh client per request", async () => {
  const calls: string[] = [];
  let clientId = 0;
  let factoryCalls = 0;
  const plugin = fakePlugin(
    async (name) => {
      calls.push(name);
      if (name === "init_client") return output(String(++clientId));
      return output(name === "invoke" ? "[]" : "null");
    },
    async () => {
      calls.push("close");
    },
  );
  const runtime = new ReusableExtismRuntime(async () => {
    factoryCalls += 1;
    return plugin;
  });

  const first = await runWithOnePasswordClient(runtime, runOptions, async (client) => {
    await client.invoke({ kind: "vault.list" });
    return "first";
  });
  const second = await runWithOnePasswordClient(runtime, runOptions, async (client) => {
    await client.invoke({ kind: "vault.list" });
    return "second";
  });

  assert.equal(factoryCalls, 1);
  assert.deepEqual(calls, [
    "init_client",
    "invoke",
    "release_client",
    "init_client",
    "invoke",
    "release_client",
  ]);
  assert.deepEqual(first, {
    cleanup: "ok",
    guestPagesAfter: 1,
    guestPagesBefore: 1,
    ok: true,
    pluginCreated: true,
    pluginDisposition: "retained",
    pluginReused: false,
    value: "first",
  });
  assert.deepEqual(second, {
    cleanup: "ok",
    guestPagesAfter: 1,
    guestPagesBefore: 1,
    ok: true,
    pluginCreated: false,
    pluginDisposition: "retained",
    pluginReused: true,
    value: "second",
  });
});

test("invoke errors are stable, release once, poison the plugin, and never leak token text", async () => {
  const calls: string[] = [];
  const plugin = fakePlugin(
    async (name) => {
      calls.push(name);
      if (name === "init_client") return output("2");
      if (name === "invoke") throw new Error(`raw upstream ${fakeServiceAccountToken}`);
      return output("null");
    },
    async () => {
      calls.push("close");
    },
  );
  const runtime = new ReusableExtismRuntime(async () => plugin);

  const outcome = await runWithOnePasswordClient(runtime, runOptions, async (client) =>
    client.invoke({ kind: "vault.list" }),
  );

  assert.deepEqual(calls, ["init_client", "invoke", "release_client", "close"]);
  assert.equal(outcome.cleanup, "ok");
  assert.equal(outcome.guestPagesBefore, 1);
  assert.equal(outcome.guestPagesAfter, 1);
  assert.equal(outcome.ok, false);
  assert.equal(outcome.pluginDisposition, "evicted");
  if (outcome.ok) return;
  assert.ok(outcome.error instanceof CoreAdapterError);
  assert.equal(outcome.error.message, "core_call_failed");
  assert.doesNotMatch(outcome.error.message, /ops_/);
});

test("an observed upstream 429 becomes a stable 1Password rate-limit error", async () => {
  const runtime = new ReusableExtismRuntime(
    async (_accountHost, _generation, getActiveLease) =>
      fakePlugin(async (name) => {
        if (name === "init_client") return output("9");
        if (name === "invoke") {
          getActiveLease()!.upstreamRateLimited = true;
          throw new Error("untrusted upstream response");
        }
        return output("null");
      }),
  );

  const outcome = await runWithOnePasswordClient(runtime, runOptions, (client) =>
    client.invoke({ kind: "vault.list" }),
  );
  assert.equal(outcome.ok, false);
  if (outcome.ok) return;
  assert.ok(outcome.error instanceof CoreAdapterError);
  assert.equal(outcome.error.code, "onepassword_rate_limited");
});

test("init failure skips release; release failure reports completed-but-unclean", async () => {
  const initCalls: string[] = [];
  const failedInit = fakePlugin(
    async (name) => {
      initCalls.push(name);
      throw new Error("raw init failure");
    },
    async () => {
      initCalls.push("close");
    },
  );
  const initOutcome = await runWithOnePasswordClient(
    new ReusableExtismRuntime(async () => failedInit),
    runOptions,
    async () => "unreachable",
  );
  assert.deepEqual(initCalls, ["init_client", "close"]);
  assert.equal(initOutcome.ok, false);
  assert.equal(initOutcome.guestPagesBefore, 1);
  assert.equal(initOutcome.guestPagesAfter, 1);
  assert.equal(initOutcome.pluginDisposition, "evicted");
  if (initOutcome.ok) return;
  assert.ok(initOutcome.error instanceof CoreAdapterError);

  const releaseCalls: string[] = [];
  const failedRelease = fakePlugin(
    async (name) => {
      releaseCalls.push(name);
      if (name === "init_client") return output("3");
      if (name === "release_client") throw new Error("release failed");
      return output("null");
    },
    async () => {
      releaseCalls.push("close");
    },
  );
  const releaseOutcome = await runWithOnePasswordClient(
    new ReusableExtismRuntime(async () => failedRelease),
    runOptions,
    async () => "mutation_succeeded",
  );
  assert.deepEqual(releaseCalls, ["init_client", "release_client", "close"]);
  assert.equal(releaseOutcome.ok, false);
  assert.equal(releaseOutcome.cleanup, "release_failed");
  assert.equal(releaseOutcome.guestPagesBefore, 1);
  assert.equal(releaseOutcome.guestPagesAfter, 1);
  assert.equal(releaseOutcome.pluginCreated, true);
  assert.equal(releaseOutcome.pluginDisposition, "evicted");
  assert.equal(releaseOutcome.pluginReused, false);
  if (releaseOutcome.ok || !releaseOutcome.operationCompleted) return;
  assert.equal(releaseOutcome.value, "mutation_succeeded");
  assert.ok(releaseOutcome.error instanceof CoreAdapterError);
  assert.equal(releaseOutcome.error.stage, "client.release");
  assert.equal(releaseOutcome.error.code, "client_release_failed");
});

test("invalid service-account token fails before touching a healthy cached plugin", async () => {
  let factoryCalls = 0;
  let pluginCalls = 0;
  const runtime = new ReusableExtismRuntime(async () => {
    factoryCalls += 1;
    return fakePlugin(async (name) => {
      pluginCalls += 1;
      return output(name === "init_client" ? "4" : "null");
    });
  });

  const first = await runWithOnePasswordClient(runtime, runOptions, async () => "ok");
  assert.equal(first.ok, true);
  const invalid = await runWithOnePasswordClient(
    runtime,
    { ...runOptions, serviceAccountToken: "not-a-token" },
    async () => "unreachable",
  );
  assert.equal(invalid.ok, false);
  assert.equal(invalid.guestPagesBefore, null);
  assert.equal(invalid.guestPagesAfter, null);
  assert.equal(invalid.pluginDisposition, "not_used");
  const second = await runWithOnePasswordClient(runtime, runOptions, async () => "ok-again");

  assert.equal(second.ok, true);
  assert.equal(second.pluginReused, true);
  assert.equal(factoryCalls, 1);
  assert.equal(pluginCalls, 4);
});

test("a post-operation eviction failure is completed-but-failed and must not be retried", async () => {
  const calls: string[] = [];
  let operationCalls = 0;
  const plugin = fakePlugin(
    async (name) => {
      calls.push(name);
      if (name === "init_client") return output("5");
      return output("null");
    },
    async () => {
      calls.push("close");
      throw new Error("simulated close failure");
    },
  );
  const runtime = new ReusableExtismRuntime(async () => plugin, { maximumUses: 1 });

  const outcome = await runWithOnePasswordClient(runtime, runOptions, async () => {
    operationCalls += 1;
    return "mutation_succeeded";
  });

  assert.deepEqual(calls, ["init_client", "release_client", "close"]);
  assert.equal(operationCalls, 1);
  assert.equal(outcome.ok, false);
  assert.equal(outcome.cleanup, "ok");
  assert.equal(outcome.guestPagesBefore, 1);
  assert.equal(outcome.guestPagesAfter, 1);
  assert.equal(outcome.pluginDisposition, "evict_failed");
  if (outcome.ok || !outcome.operationCompleted) return;
  assert.equal(outcome.operationCompleted, true);
  assert.equal(outcome.value, "mutation_succeeded");
  assert.ok(outcome.error instanceof CoreAdapterError);
  assert.equal(outcome.error.stage, "plugin.close");
  assert.equal(outcome.error.code, "plugin_evict_failed");
});

function output(text: string): any {
  const bytes = encoder.encode(text);
  return { bytes: () => bytes };
}

function fakePlugin(
  call: (name: string, input?: string | number | Uint8Array) => Promise<any>,
  close: () => Promise<void> = async () => {},
): CachedExtismPlugin {
  const memory = new WebAssembly.Memory({ initial: 1 });
  let active = false;
  return {
    async call(name, input) {
      active = true;
      try {
        return await call(name, input);
      } finally {
        active = false;
      }
    },
    close,
    async getExports() {
      return [];
    },
    async getImports() {
      return [];
    },
    async getInstance() {
      return { exports: { memory } } as unknown as WebAssembly.Instance;
    },
    isActive() {
      return active;
    },
  } as CachedExtismPlugin;
}
