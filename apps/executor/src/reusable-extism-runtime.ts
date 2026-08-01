import type { Plugin } from "@extism/extism";

import { normalizeAccountHost } from "./account";
import { AsyncMutex } from "./mutex";

const WASM_PAGE_BYTES = 64 * 1024;
const DEFAULT_MAX_GUEST_PAGES = 512;
const DEFAULT_MAX_USES = 128;
const DEFAULT_MAX_AGE_MS = 10 * 60_000;

export interface ActivePluginLease {
  aborted: boolean;
  deadlineAt: number;
  generation: number;
  signal: AbortSignal;
}

export type CachedExtismPlugin = Pick<
  Plugin,
  | "call"
  | "close"
  | "getExports"
  | "getImports"
  | "getInstance"
  | "isActive"
>;

export type PluginDisposition = "retained" | "evicted" | "evict_failed";
export type PluginTimingStage = "plugin.create" | "plugin.close";
export type PluginRuntimeFailureCode =
  | "mutex_queue_full"
  | "operation_aborted"
  | "operation_deadline_exceeded"
  | "operation_failed"
  | "plugin_create_failed"
  | "plugin_evict_failed";

export interface PluginLease {
  callRequired(
    name: "init_client" | "invoke" | "release_client",
    input: Uint8Array,
  ): Promise<Uint8Array>;
  getExports(): Promise<WebAssembly.ModuleExportDescriptor[]>;
  getImports(): Promise<WebAssembly.ModuleImportDescriptor[]>;
  poison(): void;
}

export interface PluginLeaseOptions {
  accountHost: string;
  credentialDigest?: string;
  deadlineAt: number;
  signal?: AbortSignal;
}

export interface PluginLeaseOutcome<T> {
  guestPagesAfter: number;
  guestPagesBefore: number;
  pluginCreated: boolean;
  pluginDisposition: PluginDisposition;
  pluginReused: boolean;
  value: T;
}

export interface PluginRuntime {
  withLease<T>(
    options: PluginLeaseOptions,
    operation: (lease: PluginLease) => Promise<T>,
    observeTiming?: (stage: PluginTimingStage, durationMs: number) => void,
  ): Promise<PluginLeaseOutcome<T>>;
}

export type CachedPluginFactory = (
  accountHost: string,
  generation: number,
  getActiveLease: () => ActivePluginLease | undefined,
) => Promise<CachedExtismPlugin>;

interface CacheEntry {
  accountHost: string;
  createdAt: number;
  credentialDigest?: string;
  generation: number;
  plugin: CachedExtismPlugin;
  uses: number;
}

interface RuntimeLimits {
  maximumAgeMs?: number;
  maximumGuestPages?: number;
  maximumPending?: number;
  maximumUses?: number;
}

export class ReusableExtismRuntimeError extends Error {
  constructor(
    readonly stage: "operation" | PluginTimingStage,
    readonly pluginDisposition: PluginDisposition | "not_used",
    readonly pluginCreated: boolean,
    readonly pluginReused: boolean,
    readonly code: PluginRuntimeFailureCode = defaultFailureCode(stage),
    readonly guestPagesBefore: number | null = null,
    readonly guestPagesAfter: number | null = null,
  ) {
    super(code);
    this.name = "ReusableExtismRuntimeError";
  }
}

export class ReusableExtismRuntime implements PluginRuntime {
  #activeLease: ActivePluginLease | undefined;
  #entry: CacheEntry | undefined;
  #factory: CachedPluginFactory;
  #generation = 0;
  #maximumAgeMs: number;
  #maximumGuestPages: number;
  #maximumUses: number;
  #mutex: AsyncMutex;

  constructor(factory: CachedPluginFactory, limits: RuntimeLimits = {}) {
    this.#factory = factory;
    this.#maximumAgeMs = limits.maximumAgeMs ?? DEFAULT_MAX_AGE_MS;
    this.#maximumGuestPages = limits.maximumGuestPages ?? DEFAULT_MAX_GUEST_PAGES;
    this.#maximumUses = limits.maximumUses ?? DEFAULT_MAX_USES;
    this.#mutex = new AsyncMutex(limits.maximumPending ?? 64);
    if (
      this.#maximumAgeMs <= 0 ||
      this.#maximumGuestPages <= 0 ||
      this.#maximumUses <= 0
    ) {
      throw new RangeError("invalid_reusable_runtime_limit");
    }
  }

  async withLease<T>(
    options: PluginLeaseOptions,
    operation: (lease: PluginLease) => Promise<T>,
    observeTiming?: (stage: PluginTimingStage, durationMs: number) => void,
  ): Promise<PluginLeaseOutcome<T>> {
    const accountHost = normalizeAccountHost(options.accountHost);
    validateDeadline(options.deadlineAt);
    validateCredentialDigest(options.credentialDigest);
    const scope = createAbortScope(options.deadlineAt, options.signal);

    try {
      return await this.#mutex.runExclusive(
        () =>
          this.#runLocked(
            { ...options, accountHost, signal: scope.signal },
            operation,
            observeTiming,
          ),
        scope.signal,
      );
    } catch (error) {
      if (error instanceof ReusableExtismRuntimeError) throw error;
      if (error instanceof DOMException && error.name === "TimeoutError") {
        throw new ReusableExtismRuntimeError(
          "operation",
          "not_used",
          false,
          false,
          "operation_deadline_exceeded",
        );
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new ReusableExtismRuntimeError(
          "operation",
          "not_used",
          false,
          false,
          "operation_aborted",
        );
      }
      if (error instanceof Error && error.message === "mutex_queue_full") {
        throw new ReusableExtismRuntimeError(
          "operation",
          "not_used",
          false,
          false,
          "mutex_queue_full",
        );
      }
      throw error;
    } finally {
      scope.dispose();
    }
  }

  async #runLocked<T>(
    options: PluginLeaseOptions & { signal: AbortSignal },
    operation: (lease: PluginLease) => Promise<T>,
    observeTiming?: (stage: PluginTimingStage, durationMs: number) => void,
  ): Promise<PluginLeaseOutcome<T>> {
    options.signal.throwIfAborted();

    if (
      this.#entry !== undefined &&
      (this.#entry.uses >= this.#maximumUses ||
        Date.now() - this.#entry.createdAt >= this.#maximumAgeMs)
    ) {
      const disposition = await this.#evict(observeTiming);
      if (disposition === "evict_failed") {
        throw new ReusableExtismRuntimeError("plugin.close", disposition, false, false);
      }
    }

    const identityChanged =
      this.#entry !== undefined &&
      (this.#entry.accountHost !== options.accountHost ||
        (options.credentialDigest !== undefined &&
          this.#entry.credentialDigest !== undefined &&
          this.#entry.credentialDigest !== options.credentialDigest));
    if (identityChanged) {
      const disposition = await this.#evict(observeTiming);
      if (disposition === "evict_failed") {
        throw new ReusableExtismRuntimeError("plugin.close", disposition, false, false);
      }
    }
    options.signal.throwIfAborted();

    let entry = this.#entry;
    let pluginCreated = false;
    let pluginReused = entry !== undefined;
    const generation = entry?.generation ?? ++this.#generation;
    const activeLease: ActivePluginLease = {
      aborted: options.signal.aborted,
      deadlineAt: options.deadlineAt,
      generation,
      signal: options.signal,
    };
    const markAborted = (): void => {
      activeLease.aborted = true;
    };
    options.signal.addEventListener("abort", markAborted, { once: true });
    this.#activeLease = activeLease;

    try {
      if (!entry) {
        let plugin: CachedExtismPlugin;
        try {
          plugin = await timed(
            "plugin.create",
            () => this.#factory(options.accountHost, generation, () => this.#activeLease),
            observeTiming,
          );
        } catch {
          throw new ReusableExtismRuntimeError("plugin.create", "not_used", false, false);
        }
        entry = {
          accountHost: options.accountHost,
          createdAt: Date.now(),
          ...(options.credentialDigest === undefined
            ? {}
            : { credentialDigest: options.credentialDigest }),
          generation,
          plugin,
          uses: 0,
        };
        this.#entry = entry;
        pluginCreated = true;
        pluginReused = false;
      } else if (
        entry.credentialDigest === undefined &&
        options.credentialDigest !== undefined
      ) {
        entry.credentialDigest = options.credentialDigest;
      }
      if (!entry) {
        throw new ReusableExtismRuntimeError(
          "plugin.create",
          "not_used",
          pluginCreated,
          pluginReused,
        );
      }

      let pluginActive: boolean;
      try {
        pluginActive = entry.plugin.isActive();
      } catch {
        pluginActive = true;
      }
      if (pluginActive || options.signal.aborted) {
        const disposition = await this.#evict(observeTiming);
        throw new ReusableExtismRuntimeError(
          "operation",
          disposition,
          pluginCreated,
          pluginReused,
        );
      }

      let guestMemory: WebAssembly.Memory;
      let guestPagesBefore: number;
      try {
        const instance = await entry.plugin.getInstance();
        const memory = instance.exports.memory;
        if (!(memory instanceof WebAssembly.Memory)) {
          throw new Error("guest_memory_unavailable");
        }
        guestMemory = memory;
        guestPagesBefore = guestPageCount(guestMemory);
      } catch {
        const disposition = await this.#evict(observeTiming);
        throw new ReusableExtismRuntimeError(
          "operation",
          disposition,
          pluginCreated,
          pluginReused,
        );
      }

      const lease = new RuntimePluginLease(entry.plugin);
      let value: T;
      try {
        value = await operation(lease);
      } catch {
        lease.markPoisoned();
        lease.revoke();
        await lease.settle();
        const guestPagesAfter = guestPageCount(guestMemory);
        const disposition = await this.#evict(observeTiming);
        throw new ReusableExtismRuntimeError(
          "operation",
          disposition,
          pluginCreated,
          pluginReused,
          abortFailureCode(options.signal),
          guestPagesBefore,
          guestPagesAfter,
        );
      }
      if (lease.inFlight > 0) lease.markPoisoned();
      lease.revoke();
      await lease.settle();
      const guestPagesAfter = guestPageCount(guestMemory);

      entry.uses += 1;
      const shouldRotate = this.#shouldRotate(
        entry,
        lease.poisoned,
        guestPagesAfter,
      );
      const disposition = shouldRotate
        ? await this.#evict(observeTiming)
        : "retained";
      if (options.signal.aborted) {
        throw new ReusableExtismRuntimeError(
          "operation",
          disposition === "retained" ? await this.#evict(observeTiming) : disposition,
          pluginCreated,
          pluginReused,
          options.signal.reason instanceof DOMException &&
            options.signal.reason.name === "TimeoutError"
            ? "operation_deadline_exceeded"
            : "operation_aborted",
          guestPagesBefore,
          guestPagesAfter,
        );
      }
      return {
        guestPagesAfter,
        guestPagesBefore,
        pluginCreated,
        pluginDisposition: disposition,
        pluginReused,
        value,
      };
    } finally {
      options.signal.removeEventListener("abort", markAborted);
      if (this.#activeLease === activeLease) {
        this.#activeLease = undefined;
      }
    }
  }

  #shouldRotate(
    entry: CacheEntry,
    poisoned: boolean,
    guestPagesAfter: number,
  ): boolean {
    if (
      poisoned ||
      this.#activeLease?.aborted ||
      entry.uses >= this.#maximumUses ||
      Date.now() - entry.createdAt >= this.#maximumAgeMs
    ) {
      return true;
    }

    try {
      if (entry.plugin.isActive()) return true;
      return guestPagesAfter > this.#maximumGuestPages;
    } catch {
      return true;
    }
  }

  async #evict(
    observeTiming?: (stage: PluginTimingStage, durationMs: number) => void,
  ): Promise<Extract<PluginDisposition, "evicted" | "evict_failed">> {
    const entry = this.#entry;
    this.#entry = undefined;
    if (!entry) return "evicted";

    let failed = false;
    await timed(
      "plugin.close",
      async () => {
        try {
          if (entry.plugin.isActive()) {
            failed = true;
          } else {
            const instance = await entry.plugin.getInstance();
            const memory = instance.exports.memory;
            if (memory instanceof WebAssembly.Memory) {
              new Uint8Array(memory.buffer).fill(0);
            } else {
              failed = true;
            }
          }
        } catch {
          failed = true;
        }

        try {
          await entry.plugin.close();
        } catch {
          failed = true;
        }
      },
      observeTiming,
    );
    return failed ? "evict_failed" : "evicted";
  }
}

class RuntimePluginLease implements PluginLease {
  #inFlight = new Set<Promise<unknown>>();
  #plugin: CachedExtismPlugin;
  #poisoned = false;
  #revoked = false;

  constructor(plugin: CachedExtismPlugin) {
    this.#plugin = plugin;
  }

  get poisoned(): boolean {
    return this.#poisoned;
  }

  get inFlight(): number {
    return this.#inFlight.size;
  }

  async callRequired(
    name: "init_client" | "invoke" | "release_client",
    input: Uint8Array,
  ): Promise<Uint8Array> {
    this.#assertActive();
    return this.#track(async () => {
      try {
        const output = await this.#plugin.call(name, input);
        this.#assertActive();
        if (output === null) throw new Error("empty_plugin_output");
        return output.bytes();
      } catch (error) {
        console.error(
          JSON.stringify({
            event: "executor_plugin_call_failed",
            failureType: classifyPluginCallFailure(error),
            function: name,
          }),
        );
        this.markPoisoned();
        throw new Error("plugin_call_failed");
      }
    });
  }

  async getExports(): Promise<WebAssembly.ModuleExportDescriptor[]> {
    this.#assertActive();
    return this.#track(async () => {
      try {
        const exports = await this.#plugin.getExports();
        this.#assertActive();
        return exports;
      } catch {
        this.markPoisoned();
        throw new Error("plugin_exports_failed");
      }
    });
  }

  async getImports(): Promise<WebAssembly.ModuleImportDescriptor[]> {
    this.#assertActive();
    return this.#track(async () => {
      try {
        const imports = await this.#plugin.getImports();
        this.#assertActive();
        return imports;
      } catch {
        this.markPoisoned();
        throw new Error("plugin_imports_failed");
      }
    });
  }

  poison(): void {
    this.#assertActive();
    this.markPoisoned();
  }

  markPoisoned(): void {
    this.#poisoned = true;
  }

  revoke(): void {
    this.#revoked = true;
  }

  async settle(): Promise<void> {
    await Promise.allSettled(this.#inFlight);
  }

  #track<T>(operation: () => Promise<T>): Promise<T> {
    let pending!: Promise<T>;
    pending = operation().finally(() => {
      this.#inFlight.delete(pending);
    });
    this.#inFlight.add(pending);
    return pending;
  }

  #assertActive(): void {
    if (this.#revoked) throw new Error("plugin_lease_revoked");
  }
}

function classifyPluginCallFailure(error: unknown): string {
  if (error instanceof WebAssembly.RuntimeError) return "wasm_runtime_error";
  if (error instanceof DOMException) {
    if (error.name === "AbortError") return "operation_aborted";
    if (error.name === "TimeoutError") return "operation_deadline_exceeded";
    return "dom_exception";
  }
  if (error instanceof TypeError) return "type_error";
  if (error instanceof RangeError) return "range_error";
  if (error instanceof Error) {
    if (error.message === "empty_plugin_output") return "empty_plugin_output";
    if (error.message.startsWith("Plugin-originated error:")) {
      return "plugin_originated_error";
    }
    if (error.message.startsWith("EXTISM:")) return "extism_runtime_error";
  }
  return "unexpected_error";
}

function createAbortScope(
  deadlineAt: number,
  sourceSignal?: AbortSignal,
): { dispose: () => void; signal: AbortSignal } {
  const controller = new AbortController();
  const remainingMs = deadlineAt - Date.now();
  const timeoutReason = new DOMException("operation deadline exceeded", "TimeoutError");
  const timer =
    remainingMs <= 0
      ? undefined
      : setTimeout(() => controller.abort(timeoutReason), remainingMs);
  if (remainingMs <= 0) controller.abort(timeoutReason);
  const abortFromSource = (): void => {
    controller.abort(new DOMException("operation aborted", "AbortError"));
  };
  if (sourceSignal?.aborted) {
    abortFromSource();
  } else {
    sourceSignal?.addEventListener("abort", abortFromSource, { once: true });
  }

  return {
    dispose: () => {
      if (timer !== undefined) clearTimeout(timer);
      sourceSignal?.removeEventListener("abort", abortFromSource);
      controller.abort(new DOMException("plugin lease disposed", "AbortError"));
    },
    signal: controller.signal,
  };
}

function defaultFailureCode(
  stage: "operation" | PluginTimingStage,
): PluginRuntimeFailureCode {
  if (stage === "plugin.create") return "plugin_create_failed";
  if (stage === "plugin.close") return "plugin_evict_failed";
  return "operation_failed";
}

function abortFailureCode(signal: AbortSignal): PluginRuntimeFailureCode {
  if (!signal.aborted) return "operation_failed";
  return signal.reason instanceof DOMException && signal.reason.name === "TimeoutError"
    ? "operation_deadline_exceeded"
    : "operation_aborted";
}

function guestPageCount(memory: WebAssembly.Memory): number {
  const pages = memory.buffer.byteLength / WASM_PAGE_BYTES;
  if (!Number.isSafeInteger(pages) || pages < 0) {
    throw new Error("invalid_guest_memory_size");
  }
  return pages;
}

function validateDeadline(deadlineAt: number): void {
  if (!Number.isSafeInteger(deadlineAt) || deadlineAt <= 0) {
    throw new RangeError("invalid_operation_deadline");
  }
}

function validateCredentialDigest(credentialDigest: string | undefined): void {
  if (credentialDigest !== undefined && !/^[a-f0-9]{64}$/.test(credentialDigest)) {
    throw new Error("invalid_credential_digest");
  }
}

async function timed<T>(
  stage: PluginTimingStage,
  operation: () => Promise<T>,
  observeTiming?: (stage: PluginTimingStage, durationMs: number) => void,
): Promise<T> {
  const startedAt = performance.now();
  try {
    return await operation();
  } finally {
    observeTiming?.(stage, performance.now() - startedAt);
  }
}
