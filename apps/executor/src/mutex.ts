interface Waiter {
  cancelled: boolean;
  cleanupAbort: () => void;
  grant: (release: () => void) => void;
  reject: (reason: unknown) => void;
}

export class MutexQueueFullError extends Error {
  constructor() {
    super("mutex_queue_full");
    this.name = "MutexQueueFullError";
  }
}

export class AsyncMutex {
  #locked = false;
  #maximumPending: number;
  #queue: Waiter[] = [];

  constructor(maximumPending = 64) {
    if (!Number.isSafeInteger(maximumPending) || maximumPending < 1) {
      throw new RangeError("invalid_mutex_queue_limit");
    }
    this.#maximumPending = maximumPending;
  }

  async runExclusive<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const release = await this.#acquire(signal);
    try {
      signal?.throwIfAborted();
      return await operation();
    } finally {
      release();
    }
  }

  #acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) return Promise.reject(abortReason(signal));
    if (!this.#locked) {
      this.#locked = true;
      return Promise.resolve(() => this.#release());
    }
    if (this.#queue.length >= this.#maximumPending) {
      return Promise.reject(new MutexQueueFullError());
    }

    return new Promise<() => void>((grant, reject) => {
      const waiter: Waiter = {
        cancelled: false,
        cleanupAbort: () => {},
        grant,
        reject,
      };
      if (signal) {
        const onAbort = (): void => {
          if (waiter.cancelled) return;
          waiter.cancelled = true;
          signal.removeEventListener("abort", onAbort);
          waiter.cleanupAbort = () => {};
          reject(abortReason(signal));
        };
        signal.addEventListener("abort", onAbort, { once: true });
        waiter.cleanupAbort = () => signal.removeEventListener("abort", onAbort);
      }
      this.#queue.push(waiter);
    });
  }

  #release(): void {
    let waiter = this.#queue.shift();
    while (waiter?.cancelled) {
      waiter.cleanupAbort();
      waiter = this.#queue.shift();
    }
    if (!waiter) {
      this.#locked = false;
      return;
    }

    waiter.cleanupAbort();
    waiter.grant(() => this.#release());
  }
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("operation aborted", "AbortError");
}
