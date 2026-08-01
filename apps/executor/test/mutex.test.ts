import assert from "node:assert/strict";
import test from "node:test";

import { AsyncMutex } from "../src/mutex.ts";

test("AsyncMutex serializes concurrent work in FIFO order", async () => {
  const mutex = new AsyncMutex();
  const order: number[] = [];
  let active = 0;
  let maximumActive = 0;

  await Promise.all(
    Array.from({ length: 50 }, (_, index) =>
      mutex.runExclusive(async () => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        order.push(index);
        await Promise.resolve();
        active -= 1;
      }),
    ),
  );

  assert.equal(maximumActive, 1);
  assert.deepEqual(order, Array.from({ length: 50 }, (_, index) => index));
});

test("AsyncMutex releases the queue after rejection", async () => {
  const mutex = new AsyncMutex();
  await assert.rejects(
    mutex.runExclusive(async () => {
      throw new Error("expected test failure");
    }),
    /expected test failure/,
  );
  assert.equal(await mutex.runExclusive(async () => "continued"), "continued");
});

test("AsyncMutex does not enter the next operation before the active call settles", async () => {
  const mutex = new AsyncMutex();
  let finishFirst!: () => void;
  let secondEntered = false;

  const first = mutex.runExclusive(
    () =>
      new Promise<void>((resolve) => {
        finishFirst = resolve;
      }),
  );
  await Promise.resolve();
  const second = mutex.runExclusive(async () => {
    secondEntered = true;
  });

  await Promise.resolve();
  assert.equal(secondEntered, false);
  finishFirst();
  await Promise.all([first, second]);
  assert.equal(secondEntered, true);
});

test("AsyncMutex removes an aborted waiter without running its operation", async () => {
  const mutex = new AsyncMutex();
  let finishFirst!: () => void;
  let cancelledEntered = false;
  let thirdEntered = false;
  const first = mutex.runExclusive(
    () =>
      new Promise<void>((resolve) => {
        finishFirst = resolve;
      }),
  );
  await Promise.resolve();

  const controller = new AbortController();
  const cancelled = mutex.runExclusive(async () => {
    cancelledEntered = true;
  }, controller.signal);
  const third = mutex.runExclusive(async () => {
    thirdEntered = true;
  });
  controller.abort();

  await assert.rejects(cancelled, { name: "AbortError" });
  assert.equal(cancelledEntered, false);
  assert.equal(thirdEntered, false);
  finishFirst();
  await Promise.all([first, third]);
  assert.equal(cancelledEntered, false);
  assert.equal(thirdEntered, true);
});

test("AsyncMutex bounds pending work", async () => {
  const mutex = new AsyncMutex(1);
  let finishFirst!: () => void;
  const first = mutex.runExclusive(
    () =>
      new Promise<void>((resolve) => {
        finishFirst = resolve;
      }),
  );
  await Promise.resolve();
  const second = mutex.runExclusive(async () => {});
  await assert.rejects(mutex.runExclusive(async () => {}), /mutex_queue_full/);
  finishFirst();
  await Promise.all([first, second]);
});
