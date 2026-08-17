import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import vm from "node:vm";

import { finalizeServiceWorker } from "../scripts/finalize-service-worker.mjs";

test("the built service worker precaches the final hashed JavaScript and CSS", async () => {
  const root = await mkdtemp(join(tmpdir(), "onenod-service-worker-"));
  try {
    await mkdir(join(root, "assets"));
    await Promise.all([
      writeFile(join(root, "index.html"), '<script src="/assets/app-123.js"></script><link rel="stylesheet" href="/assets/app-123.css">'),
      writeFile(join(root, "assets/app-123.js"), "console.log('onenod')"),
      writeFile(join(root, "assets/app-123.css"), "body{background:#000}"),
      writeFile(join(root, "manifest.webmanifest"), "{}"),
      writeFile(join(root, "icon.svg"), "<svg></svg>"),
      writeFile(join(root, "icon-192.png"), "192"),
      writeFile(join(root, "icon-512.png"), "512"),
      writeFile(join(root, "apple-touch-icon.png"), "apple"),
      readFile(new URL("../public/service-worker.js", import.meta.url), "utf8")
        .then((source) => writeFile(join(root, "service-worker.js"), source)),
    ]);

    const result = await finalizeServiceWorker(root);
    assert.match(result.cacheName, /^onenod-shell-[a-f0-9]{20}$/u);
    assert.deepEqual(result.urls, [
      "/apple-touch-icon.png",
      "/assets/app-123.css",
      "/assets/app-123.js",
      "/icon-192.png",
      "/icon-512.png",
      "/icon.svg",
      "/manifest.webmanifest",
      "/requests",
    ]);
    const output = await readFile(join(root, "service-worker.js"), "utf8");
    assert.ok(output.includes(JSON.stringify(result.cacheName)));
    assert.ok(output.includes('"/assets/app-123.js"'));
    assert.ok(output.includes('"/assets/app-123.css"'));
    assert.ok(!output.includes('const CACHE_NAME = "onenod-shell-dev"'));
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("offline navigation uses only the cached app shell and assets never receive HTML fallback", async () => {
  const source = await readFile(
    new URL("../public/service-worker.js", import.meta.url),
    "utf8",
  );
  const listeners = new Map<string, (event: unknown) => void>();
  const shell = { kind: "shell" };
  const cachedAsset = { kind: "asset" };
  const self = {
    addEventListener(name: string, listener: (event: unknown) => void) {
      listeners.set(name, listener);
    },
    clients: { claim: async () => undefined, matchAll: async () => [] },
    location: { origin: "https://onenod.example-account.workers.dev" },
    navigator: {},
    registration: { showNotification: async () => undefined },
    skipWaiting() {},
  };
  const caches = {
    delete: async () => true,
    keys: async () => [],
    match: async (key: string) =>
      key === "/requests" ? shell : key === "/assets/cached.js" ? cachedAsset : undefined,
    open: async () => ({
      addAll: async () => undefined,
      put: async () => undefined,
    }),
  };
  const fetch = async () => {
    throw new Error("offline");
  };
  const Response = { error: () => ({ kind: "network-error" }) };
  vm.runInNewContext(source, { caches, console, fetch, Promise, Response, self, Set, URL });

  const handleFetch = listeners.get("fetch");
  assert.ok(handleFetch);
  const dispatch = (pathname: string, mode: string) => {
    let response: Promise<unknown> | undefined;
    handleFetch({
      request: {
        method: "GET",
        mode,
        url: `https://onenod.example-account.workers.dev${pathname}`,
      },
      respondWith(value: Promise<unknown>) {
        response = value;
      },
    });
    return response;
  };

  await assert.doesNotReject(async () => {
    assert.equal(await dispatch("/activity", "navigate"), shell);
  });
  assert.equal(await dispatch("/assets/cached.js", "no-cors"), cachedAsset);
  await assert.rejects(dispatch("/assets/missing.js", "no-cors")!);
  assert.equal(dispatch("/v1/human/state", "cors"), undefined);
});

test("a rejected app badge update cannot turn a visible push into a failed event", async () => {
  const source = await readFile(
    new URL("../public/service-worker.js", import.meta.url),
    "utf8",
  );
  const listeners = new Map<string, (event: unknown) => void>();
  const shown: Array<{ options: Record<string, unknown>; title: string }> = [];

  const self = {
    addEventListener(name: string, listener: (event: unknown) => void) {
      listeners.set(name, listener);
    },
    clients: {
      claim: async () => undefined,
      matchAll: async () => [],
      openWindow: async () => undefined,
    },
    location: { origin: "https://onenod.example-account.workers.dev" },
    navigator: {
      setAppBadge: async () => {
        throw new Error("badge_unavailable");
      },
    },
    registration: {
      showNotification: async (title: string, options: Record<string, unknown>) => {
        shown.push({ options, title });
      },
    },
    skipWaiting() {},
  };
  const caches = {
    delete: async () => true,
    keys: async () => [],
    match: async () => undefined,
    open: async () => ({ addAll: async () => undefined }),
  };

  vm.runInNewContext(source, { caches, console, Promise, self, URL });

  const push = listeners.get("push");
  assert.ok(push);
  let lifetime: Promise<unknown> | undefined;
  push({
    data: {
      json: () => ({
        body: "Open the approval queue to approve or deny this request.",
        tag: "request-test",
        title: "New 1Password approval request",
        url: "/requests#request-test",
      }),
    },
    waitUntil(promise: Promise<unknown>) {
      lifetime = promise;
    },
  });

  assert.ok(lifetime);
  await assert.doesNotReject(lifetime);
  assert.equal(shown.length, 1);
  assert.equal(shown[0]?.title, "New 1Password approval request");
  const data = shown[0]?.options.data as { url?: unknown } | undefined;
  assert.equal(data?.url, "/requests#request-test");
});

test("a notification click focuses the selected app client before and after navigation", async () => {
  const source = await readFile(
    new URL("../public/service-worker.js", import.meta.url),
    "utf8",
  );
  const listeners = new Map<string, (event: unknown) => void>();
  const calls: string[] = [];
  const navigatedClient = {
    async focus() {
      calls.push("focus:navigated");
      return navigatedClient;
    },
  };
  const appClient = {
    focused: false,
    url: "https://onenod.example-account.workers.dev/requests",
    visibilityState: "visible",
    async focus() {
      calls.push("focus:existing");
      return appClient;
    },
    async navigate(url: string) {
      calls.push(`navigate:${url}`);
      return navigatedClient;
    },
  };
  const self = {
    addEventListener(name: string, listener: (event: unknown) => void) {
      listeners.set(name, listener);
    },
    clients: {
      claim: async () => undefined,
      matchAll: async () => [appClient],
      openWindow: async () => {
        throw new Error("unexpected_open_window");
      },
    },
    location: { origin: "https://onenod.example-account.workers.dev" },
    navigator: {
      async clearAppBadge() {
        calls.push("badge:clear");
      },
    },
    registration: { showNotification: async () => undefined },
    skipWaiting() {},
  };
  const caches = {
    delete: async () => true,
    keys: async () => [],
    match: async () => undefined,
    open: async () => ({ addAll: async () => undefined }),
  };
  vm.runInNewContext(source, { caches, console, Promise, self, URL });

  const notificationClick = listeners.get("notificationclick");
  assert.ok(notificationClick);
  let lifetime: Promise<unknown> | undefined;
  notificationClick({
    notification: {
      close() {
        calls.push("close");
      },
      data: { url: "/requests#request-request-id" },
    },
    waitUntil(promise: Promise<unknown>) {
      lifetime = promise;
    },
  });

  assert.ok(lifetime);
  await assert.doesNotReject(lifetime);
  assert.deepEqual(calls, [
    "close",
    "badge:clear",
    "focus:existing",
    "navigate:https://onenod.example-account.workers.dev/requests#request-request-id",
    "focus:navigated",
  ]);
});

test("a rejected badge clear cannot block notification navigation", async () => {
  const source = await readFile(
    new URL("../public/service-worker.js", import.meta.url),
    "utf8",
  );
  const listeners = new Map<string, (event: unknown) => void>();
  const calls: string[] = [];
  const self = {
    addEventListener(name: string, listener: (event: unknown) => void) {
      listeners.set(name, listener);
    },
    clients: {
      claim: async () => undefined,
      matchAll: async () => [],
      openWindow: async (url: string) => {
        calls.push(`open:${url}`);
      },
    },
    location: { origin: "https://onenod.example-account.workers.dev" },
    navigator: {
      async clearAppBadge() {
        throw new Error("badge_unavailable");
      },
    },
    registration: { showNotification: async () => undefined },
    skipWaiting() {},
  };
  const caches = {
    delete: async () => true,
    keys: async () => [],
    match: async () => undefined,
    open: async () => ({ addAll: async () => undefined }),
  };

  vm.runInNewContext(source, { caches, console, Promise, self, URL });

  const notificationClick = listeners.get("notificationclick");
  assert.ok(notificationClick);
  let lifetime: Promise<unknown> | undefined;
  notificationClick({
    notification: {
      close() {
        calls.push("close");
      },
      data: { url: "/requests#request-request-id" },
    },
    waitUntil(promise: Promise<unknown>) {
      lifetime = promise;
    },
  });

  assert.ok(lifetime);
  await assert.doesNotReject(lifetime);
  assert.deepEqual(calls, [
    "close",
    "open:https://onenod.example-account.workers.dev/requests#request-request-id",
  ]);
});
