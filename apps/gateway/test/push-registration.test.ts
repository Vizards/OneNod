import assert from "node:assert/strict";
import test from "node:test";

import {
  readyPushServiceWorker,
  settlePushStep,
} from "../src/web/push-registration.js";

test("a permanently pending push operation fails within its bound", async () => {
  const pending = new Promise<never>(() => undefined);
  await assert.rejects(
    settlePushStep(pending, 5, "push_step_timed_out"),
    /push_step_timed_out/,
  );
});

test("service worker readiness cannot leave notification setup pending forever", async () => {
  let registrations = 0;
  const container = {
    ready: new Promise<ServiceWorkerRegistration>(() => undefined),
    async register() {
      registrations += 1;
      return {} as ServiceWorkerRegistration;
    },
  } as unknown as ServiceWorkerContainer;

  await assert.rejects(
    readyPushServiceWorker(container, 5),
    /notification service worker did not become ready/i,
  );
  assert.equal(registrations, 1);
});

test("a settled push operation clears its timeout path", async () => {
  await assert.doesNotReject(settlePushStep(Promise.resolve("ready"), 50));
  assert.equal(await settlePushStep(Promise.resolve("ready"), 50), "ready");
});
