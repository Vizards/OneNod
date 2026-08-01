import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

import { tokensMatch } from "../src/auth.ts";
import { createOnePasswordHostFunctions } from "../src/host-functions.ts";
import { normalizeAccountHost } from "../src/runtime.ts";

const packageRoot = resolve(import.meta.dirname, "..");

test("tokensMatch accepts only the exact token", async () => {
  assert.equal(await tokensMatch("same-token", "same-token"), true);
  assert.equal(await tokensMatch("same-token", "different-token"), false);
  assert.equal(await tokensMatch(undefined, "same-token"), false);
  assert.equal(await tokensMatch("", "same-token"), false);
});

test("host functions expose only the four required imports", () => {
  const functions = createOnePasswordHostFunctions();
  assert.deepEqual(Object.keys(functions).sort(), [
    "op-extism-core",
    "op-now",
    "op-time",
    "zxcvbn",
  ]);
  assert.deepEqual(Object.keys(functions["op-extism-core"] ?? {}), ["random_fill_imported"]);
  assert.deepEqual(Object.keys(functions["op-time"] ?? {}), ["utc_offset_seconds"]);
});

test("account host allowlist accepts only supported production regions", () => {
  assert.equal(normalizeAccountHost("https://my.1password.com"), "my.1password.com");
  assert.equal(
    normalizeAccountHost("HTTPS://Team-Engineering.1PASSWORD.CA"),
    "team-engineering.1password.ca",
  );
  assert.equal(normalizeAccountHost("team.1password.eu"), "team.1password.eu");
  assert.equal(
    normalizeAccountHost(`${"a".repeat(63)}.1password.com`),
    `${"a".repeat(63)}.1password.com`,
  );
  assert.throws(() => normalizeAccountHost("example.com"), /unsupported/);
  assert.throws(() => normalizeAccountHost("my.b5staging.com"), /unsupported/);
  assert.throws(() => normalizeAccountHost("nested.team.1password.com"), /unsupported/);
  assert.throws(() => normalizeAccountHost("-team.1password.com"), /unsupported/);
  assert.throws(() => normalizeAccountHost("team-.1password.com"), /unsupported/);
  assert.throws(
    () => normalizeAccountHost(`${"a".repeat(64)}.1password.com`),
    /unsupported/,
  );
  assert.throws(() => normalizeAccountHost("team.1password.com:443"), /unsupported/);
});

test("Free executor is one same-script SQLite Durable Object export", async () => {
  const config = JSON.parse(
    await readFile(resolve(packageRoot, "wrangler.jsonc"), "utf8"),
  ) as Record<string, unknown>;

  assert.deepEqual(config.durable_objects, {
    bindings: [
      {
        name: "ONEPASSWORD_EXECUTOR",
        class_name: "OnePasswordExecutor",
      },
    ],
  });
  assert.deepEqual(config.exports, {
    OnePasswordExecutor: {
      type: "durable-object",
      storage: "sqlite",
    },
  });
  assert.deepEqual(config.compatibility_flags, ["nodejs_compat"]);
  assert.deepEqual(config.alias, {
    "cpu-features": "./src/cpu-features-disabled.cjs",
    "safer-buffer": "./src/safer-buffer-worker.cjs",
  });
  assert.equal(Object.hasOwn(config, "migrations"), false);
});

test("production executor config is private and cannot silently inherit the test vault", async () => {
  const config = JSON.parse(
    await readFile(resolve(packageRoot, "wrangler.jsonc"), "utf8"),
  ) as Record<string, unknown> & {
    name: string;
    preview_urls: boolean;
    vars: { OP_ACCOUNT: string; OP_VAULT_ID: string };
    workers_dev: boolean;
  };

  assert.equal(config.name, "onenod-executor");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.equal(config.vars.OP_ACCOUNT, "CONFIGURE_IN_TARGET");
  assert.equal(config.vars.OP_VAULT_ID, "CONFIGURE_IN_TARGET");
  for (const field of ["routes", "containers", "services", "kv_namespaces", "d1_databases"]) {
    assert.equal(Object.hasOwn(config, field), false);
  }
});
