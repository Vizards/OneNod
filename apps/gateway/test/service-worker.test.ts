import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

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
