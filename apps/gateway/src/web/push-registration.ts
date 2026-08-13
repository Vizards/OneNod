const PUSH_STEP_TIMEOUT_MS = 15_000;

export function registerPushServiceWorker(
  container: ServiceWorkerContainer = navigator.serviceWorker,
): Promise<ServiceWorkerRegistration> {
  return container.register("/service-worker.js", { scope: "/" });
}

export async function readyPushServiceWorker(
  container: ServiceWorkerContainer = navigator.serviceWorker,
  timeoutMs = PUSH_STEP_TIMEOUT_MS,
): Promise<ServiceWorkerRegistration> {
  await settlePushStep(
    registerPushServiceWorker(container),
    timeoutMs,
    "The notification service worker could not be registered. Reload the page and try again.",
  );
  return settlePushStep(
    container.ready,
    timeoutMs,
    "The notification service worker did not become ready. Reload the page and try again.",
  );
}

export function settlePushStep<T>(
  operation: PromiseLike<T>,
  timeoutMs = PUSH_STEP_TIMEOUT_MS,
  timeoutMessage = "Notification setup took too long. Reload the page and try again.",
): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return Promise.reject(new Error("Notification setup timeout is invalid."));
  }
  return new Promise<T>((resolve, reject) => {
    const timer = globalThis.setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    void Promise.resolve(operation).then(
      (value) => {
        globalThis.clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        globalThis.clearTimeout(timer);
        reject(error);
      },
    );
  });
}
