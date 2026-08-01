import assert from "node:assert/strict";
import test from "node:test";

import { runWithOnePasswordClient } from "../src/onepassword-core.ts";
import {
  type CachedExtismPlugin,
  type PluginDisposition,
  type PluginRuntime,
  ReusableExtismRuntime,
} from "../src/reusable-extism-runtime.ts";

const ACCOUNT_HOST = "my.1password.com";
const SERVICE_ACCOUNT_TOKEN = `ops_${"i".repeat(64)}`;
const decoder = new TextDecoder();
const encoder = new TextEncoder();

interface RuntimeProbeResult {
  exportsPresent: boolean;
  importsPresent: boolean;
  pluginCreated: boolean;
  pluginDisposition: PluginDisposition;
  pluginReused: boolean;
}

async function probeExtismRuntime(
  runtime: PluginRuntime,
  accountHost: string,
  deadlineAt: number,
): Promise<RuntimeProbeResult> {
  const outcome = await runtime.withLease<{
    exportsPresent: boolean;
    importsPresent: boolean;
  }>({ accountHost, deadlineAt }, async (lease) => {
    const exports = await lease.getExports();
    const imports = await lease.getImports();
    const exported = new Set(exports.map(({ name }) => name));
    const imported = new Set(
      imports.map(({ module, name }) => `${module}.${name}`),
    );
    const exportsPresent = ["init_client", "invoke", "release_client"].every(
      (name) => exported.has(name),
    );
    const importsPresent = [
      "op-extism-core.random_fill_imported",
      "op-now.unix_time_milliseconds_imported",
      "op-time.utc_offset_seconds",
      "zxcvbn.unix_time_milliseconds_imported",
    ].every((name) => imported.has(name));
    if (!exportsPresent || !importsPresent) lease.poison();
    return { exportsPresent, importsPresent };
  });

  return {
    exportsPresent: outcome.value.exportsPresent,
    importsPresent: outcome.value.importsPresent,
    pluginCreated: outcome.pluginCreated,
    pluginDisposition: outcome.pluginDisposition,
    pluginReused: outcome.pluginReused,
  };
}

test("50 concurrent core runs reuse one plugin while keeping every client lifecycle unique and serial", async () => {
  const fake = createObservedPlugin();
  let factoryCalls = 0;
  const runtime = new ReusableExtismRuntime(async () => {
    factoryCalls += 1;
    await nextTurn();
    return fake.plugin;
  });

  const outcomes = await Promise.all(
    Array.from({ length: 50 }, (_, index) =>
      runWithOnePasswordClient(
        runtime,
        runOptions(),
        async (client) => {
          const result = await client.invoke({ kind: "vault.list" });
          assert.equal(decoder.decode(result), "[]");
          await nextTurn();
          return index;
        },
      ),
    ),
  );

  assert.equal(factoryCalls, 1);
  assert.equal(fake.closeCalls, 0);
  assert.equal(fake.maximumActiveCalls, 1);
  assert.equal(fake.maximumLiveClients, 1);
  assert.equal(fake.initClientIds.length, 50);
  assert.equal(fake.invokeClientIds.length, 50);
  assert.equal(fake.releaseClientIds.length, 50);
  assert.equal(new Set(fake.initClientIds).size, 50);
  assert.deepEqual(
    [...fake.releaseClientIds].sort(compareClientIds),
    [...fake.initClientIds].sort(compareClientIds),
  );
  assert.deepEqual(
    [...fake.invokeClientIds].sort(compareClientIds),
    [...fake.initClientIds].sort(compareClientIds),
  );
  assert.equal(outcomes.filter(({ pluginCreated }) => pluginCreated).length, 1);
  assert.equal(outcomes.filter(({ pluginReused }) => pluginReused).length, 49);
  assert.ok(
    outcomes.every(
      (outcome) => outcome.ok && outcome.pluginDisposition === "retained",
    ),
  );
  assert.deepEqual(
    outcomes.map((outcome) => {
      assert.equal(outcome.ok, true);
      return outcome.ok ? outcome.value : undefined;
    }),
    Array.from({ length: 50 }, (_, index) => index),
  );
});

test("runtime probes and core runs share one runtime, plugin, and serialization boundary in both queue orders", async () => {
  const fake = createObservedPlugin();
  let factoryCalls = 0;
  const runtime = new ReusableExtismRuntime(async () => {
    factoryCalls += 1;
    await nextTurn();
    return fake.plugin;
  });

  const probe = () =>
    probeExtismRuntime(runtime, ACCOUNT_HOST, Date.now() + 30_000);
  const business = (value: string) =>
    runWithOnePasswordClient(runtime, runOptions(), async (client) => {
      await nextTurn();
      const result = await client.invoke({ kind: "vault.list" });
      assert.equal(decoder.decode(result), "[]");
      await nextTurn();
      return value;
    });

  const probeFirst = await Promise.all([probe(), business("probe-first")]);
  const businessFirst = await Promise.all([business("business-first"), probe()]);
  const mixed = await Promise.all(
    Array.from({ length: 32 }, (_, index) =>
      index % 4 === 0 || index % 4 === 3
        ? probe()
        : business(`mixed-${index}`),
    ),
  );

  const probes = [probeFirst[0], businessFirst[1]];
  const businesses = [probeFirst[1], businessFirst[0]];
  for (let index = 0; index < mixed.length; index += 1) {
    if (index % 4 === 0 || index % 4 === 3) {
      probes.push(mixed[index] as Awaited<ReturnType<typeof probe>>);
    } else {
      businesses.push(mixed[index] as Awaited<ReturnType<typeof business>>);
    }
  }

  assert.equal(factoryCalls, 1);
  assert.equal(fake.closeCalls, 0);
  assert.equal(fake.maximumActiveCalls, 1);
  assert.equal(fake.maximumLiveClients, 1);
  assert.equal(fake.probesDuringLiveClient, 0);
  assert.equal(fake.initClientIds.length, businesses.length);
  assert.equal(fake.releaseClientIds.length, businesses.length);
  assert.equal(new Set(fake.initClientIds).size, businesses.length);
  assert.deepEqual(
    [...fake.releaseClientIds].sort(compareClientIds),
    [...fake.initClientIds].sort(compareClientIds),
  );
  assert.ok(
    probes.every(
      (outcome) =>
        outcome.exportsPresent &&
        outcome.importsPresent &&
        outcome.pluginDisposition === "retained",
    ),
  );
  assert.ok(
    businesses.every(
      (outcome) => outcome.ok && outcome.pluginDisposition === "retained",
    ),
  );
  assert.equal(
    [...probes, ...businesses].filter(({ pluginCreated }) => pluginCreated).length,
    1,
  );
  assert.equal(
    [...probes, ...businesses].filter(({ pluginReused }) => pluginReused).length,
    probes.length + businesses.length - 1,
  );
});

interface ObservedPlugin {
  closeCalls: number;
  initClientIds: string[];
  invokeClientIds: string[];
  maximumActiveCalls: number;
  maximumLiveClients: number;
  plugin: CachedExtismPlugin;
  probesDuringLiveClient: number;
  releaseClientIds: string[];
}

function createObservedPlugin(): ObservedPlugin {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const liveClientIds = new Set<string>();
  const observed: ObservedPlugin = {
    closeCalls: 0,
    initClientIds: [],
    invokeClientIds: [],
    maximumActiveCalls: 0,
    maximumLiveClients: 0,
    plugin: undefined as unknown as CachedExtismPlugin,
    probesDuringLiveClient: 0,
    releaseClientIds: [],
  };
  let activeCalls = 0;
  let nextClientId = 0;

  const tracked = async <T>(operation: () => T | Promise<T>): Promise<T> => {
    activeCalls += 1;
    observed.maximumActiveCalls = Math.max(
      observed.maximumActiveCalls,
      activeCalls,
    );
    try {
      await nextTurn();
      return await operation();
    } finally {
      activeCalls -= 1;
    }
  };
  const recordProbe = (): void => {
    if (liveClientIds.size > 0) observed.probesDuringLiveClient += 1;
  };

  observed.plugin = {
    async call(name, input) {
      return tracked(() => {
        if (name === "init_client") {
          const clientId = String(++nextClientId);
          observed.initClientIds.push(clientId);
          liveClientIds.add(clientId);
          observed.maximumLiveClients = Math.max(
            observed.maximumLiveClients,
            liveClientIds.size,
          );
          return pluginOutput(clientId);
        }
        if (name === "invoke") {
          const invocation = JSON.parse(requireByteInput(input)) as {
            invocation?: { clientId?: number };
          };
          const clientId = String(invocation.invocation?.clientId);
          assert.ok(liveClientIds.has(clientId));
          observed.invokeClientIds.push(clientId);
          return pluginOutput("[]");
        }
        if (name === "release_client") {
          const clientId = requireByteInput(input);
          assert.equal(liveClientIds.delete(clientId), true);
          observed.releaseClientIds.push(clientId);
          return pluginOutput("null");
        }
        throw new Error(`unexpected plugin call: ${name}`);
      });
    },
    async close() {
      await tracked(() => {
        observed.closeCalls += 1;
      });
    },
    async getExports() {
      return tracked(() => {
        recordProbe();
        return ["init_client", "invoke", "release_client"].map((name) => ({
          kind: "function" as const,
          name,
        }));
      });
    },
    async getImports() {
      return tracked(() => {
        recordProbe();
        return [
          ["op-extism-core", "random_fill_imported"],
          ["op-now", "unix_time_milliseconds_imported"],
          ["op-time", "utc_offset_seconds"],
          ["zxcvbn", "unix_time_milliseconds_imported"],
        ].map(([module, name]) => ({ kind: "function" as const, module, name }));
      });
    },
    async getInstance() {
      return tracked(
        () => ({ exports: { memory } }) as unknown as WebAssembly.Instance,
      );
    },
    isActive() {
      return activeCalls > 0;
    },
  } as CachedExtismPlugin;

  return observed;
}

function runOptions(): {
  accountHost: string;
  deadlineAt: number;
  serviceAccountToken: string;
} {
  return {
    accountHost: ACCOUNT_HOST,
    deadlineAt: Date.now() + 30_000,
    serviceAccountToken: SERVICE_ACCOUNT_TOKEN,
  };
}

function pluginOutput(text: string): { bytes: () => Uint8Array } {
  const bytes = encoder.encode(text);
  return { bytes: () => bytes };
}

function requireByteInput(input: string | number | Uint8Array | undefined): string {
  assert.ok(input instanceof Uint8Array);
  return decoder.decode(input);
}

function compareClientIds(left: string, right: string): number {
  return Number(left) - Number(right);
}

function nextTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
