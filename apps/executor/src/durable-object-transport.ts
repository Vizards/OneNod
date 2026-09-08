interface ExecutorStub {
  fetch(request: Request): Promise<Response>;
}

const RETRYABLE_READ_OPERATIONS = new Map([
  ["/internal/health", "health"],
  ["/internal/1password/catalog", "catalog.search"],
  ["/internal/1password/secret/metadata", "secret.metadata"],
  ["/internal/1password/item/metadata", "item.metadata"],
]);
const MAX_READ_ATTEMPTS = 3;
// One budget for all attempts and waits, below the Gateway's 90-second deadline.
const READ_TIMEOUT_MS = 80_000;
const BASE_BACKOFF_MS = 200;

export async function fetchExecutorDurableObject(
  request: Request,
  createStub: () => ExecutorStub,
): Promise<Response> {
  const operation = request.method === "POST"
    ? RETRYABLE_READ_OPERATIONS.get(new URL(request.url).pathname)
    : undefined;
  // Secret delivery, signatures, and journaled mutations retain their own semantics.
  if (operation === undefined) return createStub().fetch(request);

  const controller = new AbortController();
  const abortFromRequest = (): void => {
    controller.abort(new DOMException("executor request aborted", "AbortError"));
  };
  const timer = setTimeout(() => {
    controller.abort(new DOMException("executor read timed out", "TimeoutError"));
  }, READ_TIMEOUT_MS);
  if (request.signal.aborted) abortFromRequest();
  else request.signal.addEventListener("abort", abortFromRequest, { once: true });

  try {
    for (let attempt = 1; ; attempt += 1) {
      controller.signal.throwIfAborted();
      try {
        const response = await withAbort(() => {
          // Failed stubs may remain broken. Keep the original body for a fresh attempt.
          const copy = request.clone() as Request;
          const retryRequest = new Request(copy, { signal: controller.signal });
          return createStub().fetch(retryRequest);
        }, controller.signal);
        if (attempt > 1) {
          console.log(JSON.stringify({
            attempt,
            event: "executor_durable_object_response",
            operation,
            status: response.status,
          }));
        }
        return response;
      } catch (error) {
        const retryable = error instanceof Error &&
          "retryable" in error && error.retryable === true;
        const overloaded = error instanceof Error &&
          "overloaded" in error && error.overloaded === true;
        const cancelled = controller.signal.aborted || (error instanceof Error &&
          (error.name === "AbortError" || error.name === "TimeoutError"));
        const willRetry = retryable && !overloaded && !cancelled &&
          attempt < MAX_READ_ATTEMPTS;
        console.warn(JSON.stringify({
          attempt,
          cancelled,
          event: "executor_durable_object_failure",
          operation,
          overloaded,
          retryable,
          willRetry,
        }));
        controller.signal.throwIfAborted();
        if (!willRetry) throw error;
      }

      const backoffMs = BASE_BACKOFF_MS * 2 ** (attempt - 1) * (0.5 + Math.random() / 2);
      await waitForRetry(backoffMs, controller.signal);
    }
  } finally {
    clearTimeout(timer);
    request.signal.removeEventListener("abort", abortFromRequest);
  }
}

async function withAbort<T>(operation: () => Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let onAbort = (): void => {};
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([
      Promise.resolve().then(() => {
        signal.throwIfAborted();
        return operation();
      }),
      aborted,
    ]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

async function waitForRetry(delayMs: number, signal: AbortSignal): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await withAbort(() => new Promise<void>((resolve) => {
      timer = setTimeout(resolve, delayMs);
    }), signal);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
