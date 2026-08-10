import {
  type PluginDisposition,
  type PluginLease,
  type PluginRuntime,
  ReusableExtismRuntimeError,
} from "./reusable-extism-runtime";
import {
  type ClientIdJson,
  type OnePasswordOperation,
  WireCodecError,
  decodeClientId,
  encodeClientConfig,
  encodeClientId,
  encodeInvocation,
  validateServiceAccountToken,
} from "./onepassword-wire";

export type CorePlugin = Pick<PluginLease, "callRequired" | "poison">;
export type CoreLifecycleStage =
  | "plugin.create"
  | "client.init"
  | "client.release"
  | "plugin.close";
export type CoreCleanup = "ok" | "release_failed";
export type CorePluginDisposition = PluginDisposition | "not_used";

interface CoreLifecycleMetadata {
  cleanup: CoreCleanup;
  pluginCreated: boolean;
  pluginDisposition: CorePluginDisposition;
  pluginReused: boolean;
}

export type CoreLifecycleOutcome<T> =
  | (CoreLifecycleMetadata & {
      guestPagesAfter: number | null;
      guestPagesBefore: number | null;
    } &
      (
        | { error: unknown; ok: false; operationCompleted: false }
        | { error: unknown; ok: false; operationCompleted: true; value: T }
      ))
  | (CoreLifecycleMetadata & {
      guestPagesAfter: number;
      guestPagesBefore: number;
      ok: true;
      value: T;
    });

type ClientOperationOutcome<T> =
  | { cleanup: CoreCleanup; error: unknown; ok: false; operationCompleted: false }
  | {
      cleanup: CoreCleanup;
      error: unknown;
      ok: false;
      operationCompleted: true;
      value: T;
    }
  | { cleanup: CoreCleanup; ok: true; value: T };

export interface CoreRunOptions {
  accountHost: string;
  deadlineAt: number;
  observeInvocation?: (kind: OnePasswordOperation["kind"]) => void;
  observeUpstreamRequest?: () => void;
  serviceAccountToken: string;
  signal?: AbortSignal;
}

export class CoreAdapterError extends Error {
  constructor(
    readonly stage: CoreLifecycleStage | "operation.invoke",
    readonly code: string,
  ) {
    super(code);
    this.name = "CoreAdapterError";
  }
}

export class OnePasswordCoreClient {
  #clientId: ClientIdJson | undefined;
  #observeInvocation: ((kind: OnePasswordOperation["kind"]) => void) | undefined;
  #plugin: CorePlugin;

  constructor(
    plugin: CorePlugin,
    observeInvocation?: (kind: OnePasswordOperation["kind"]) => void,
  ) {
    this.#plugin = plugin;
    this.#observeInvocation = observeInvocation;
  }

  get initialized(): boolean {
    return this.#clientId !== undefined;
  }

  async initialize(serviceAccountToken: string): Promise<void> {
    if (this.#clientId !== undefined) {
      throw new CoreAdapterError("client.init", "client_already_initialized");
    }

    let input: Uint8Array;
    try {
      input = encodeClientConfig(serviceAccountToken);
    } catch {
      throw new CoreAdapterError("client.init", "invalid_service_account_token");
    }

    const output = await this.#call("init_client", input, "client.init");
    try {
      this.#clientId = decodeClientId(output);
    } catch {
      throw new CoreAdapterError("client.init", "invalid_client_id");
    }
  }

  async invoke(operation: OnePasswordOperation): Promise<Uint8Array> {
    if (this.#clientId === undefined) {
      throw new CoreAdapterError("operation.invoke", "client_not_initialized");
    }

    let input: Uint8Array;
    try {
      input = encodeInvocation(this.#clientId, operation);
    } catch (error) {
      if (error instanceof WireCodecError) {
        throw new CoreAdapterError("operation.invoke", "invalid_operation_input");
      }
      throw error;
    }
    this.#observeInvocation?.(operation.kind);
    return this.#call("invoke", input, "operation.invoke");
  }

  async release(): Promise<void> {
    const clientId = this.#clientId;
    this.#clientId = undefined;
    if (clientId === undefined) return;
    await this.#call("release_client", encodeClientId(clientId), "client.release");
  }

  async #call(
    exportName: "init_client" | "invoke" | "release_client",
    input: Uint8Array,
    stage: CoreLifecycleStage | "operation.invoke",
  ): Promise<Uint8Array> {
    try {
      return await this.#plugin.callRequired(exportName, input);
    } catch (error) {
      throw new CoreAdapterError(
        stage,
        error instanceof Error && error.message === "onepassword_rate_limited"
          ? "onepassword_rate_limited"
          : "core_call_failed",
      );
    }
  }
}

export async function runWithOnePasswordClient<T>(
  runtime: PluginRuntime,
  options: CoreRunOptions,
  operation: (client: OnePasswordCoreClient) => Promise<T>,
  observeTiming?: (stage: CoreLifecycleStage, durationMs: number) => void,
): Promise<CoreLifecycleOutcome<T>> {
  try {
    validateServiceAccountToken(options.serviceAccountToken);
  } catch {
    return failedBeforeLease(
      new CoreAdapterError("client.init", "invalid_service_account_token"),
    );
  }

  let credentialDigest: string;
  try {
    credentialDigest = await sha256(options.serviceAccountToken);
  } catch {
    return failedBeforeLease(
      new CoreAdapterError("client.init", "credential_fingerprint_failed"),
    );
  }

  try {
    const outcome = await runtime.withLease<ClientOperationOutcome<T>>(
      {
        accountHost: options.accountHost,
        credentialDigest,
        deadlineAt: options.deadlineAt,
        ...(options.observeUpstreamRequest === undefined
          ? {}
          : { observeUpstreamRequest: options.observeUpstreamRequest }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
      async (lease) => {
        const client = new OnePasswordCoreClient(lease, options.observeInvocation);
        let operationError: unknown;
        let operationSucceeded = false;
        let value!: T;

        try {
          await timed(
            "client.init",
            () => client.initialize(options.serviceAccountToken),
            observeTiming,
          );
          value = await operation(client);
          operationSucceeded = true;
        } catch (error) {
          operationError = error;
          lease.poison();
        }

        let releaseFailed = false;
        if (client.initialized) {
          try {
            await timed("client.release", () => client.release(), observeTiming);
          } catch {
            releaseFailed = true;
            lease.poison();
          }
        }

        const cleanup: CoreCleanup = releaseFailed ? "release_failed" : "ok";
        if (!operationSucceeded) {
          return {
            cleanup,
            error: operationError,
            ok: false,
            operationCompleted: false,
          } as const;
        }
        if (releaseFailed) {
          return {
            cleanup,
            error: new CoreAdapterError("client.release", "client_release_failed"),
            ok: false,
            operationCompleted: true,
            value,
          } as const;
        }
        return { cleanup, ok: true, value } as const;
      },
      observeTiming,
    );

    if (!outcome.value.ok) {
      if (outcome.value.operationCompleted) {
        return {
          cleanup: outcome.value.cleanup,
          error: outcome.value.error,
          guestPagesAfter: outcome.guestPagesAfter,
          guestPagesBefore: outcome.guestPagesBefore,
          ok: false,
          operationCompleted: true,
          pluginCreated: outcome.pluginCreated,
          pluginDisposition: outcome.pluginDisposition,
          pluginReused: outcome.pluginReused,
          value: outcome.value.value,
        };
      }
      return {
        cleanup: outcome.value.cleanup,
        error: outcome.value.error,
        guestPagesAfter: outcome.guestPagesAfter,
        guestPagesBefore: outcome.guestPagesBefore,
        ok: false,
        operationCompleted: false,
        pluginCreated: outcome.pluginCreated,
        pluginDisposition: outcome.pluginDisposition,
        pluginReused: outcome.pluginReused,
      };
    }
    if (outcome.pluginDisposition === "evict_failed") {
      return {
        cleanup: outcome.value.cleanup,
        error: new CoreAdapterError("plugin.close", "plugin_evict_failed"),
        guestPagesAfter: outcome.guestPagesAfter,
        guestPagesBefore: outcome.guestPagesBefore,
        ok: false,
        operationCompleted: true,
        pluginCreated: outcome.pluginCreated,
        pluginDisposition: outcome.pluginDisposition,
        pluginReused: outcome.pluginReused,
        value: outcome.value.value,
      };
    }
    return {
      cleanup: outcome.value.cleanup,
      guestPagesAfter: outcome.guestPagesAfter,
      guestPagesBefore: outcome.guestPagesBefore,
      ok: true,
      pluginCreated: outcome.pluginCreated,
      pluginDisposition: outcome.pluginDisposition,
      pluginReused: outcome.pluginReused,
      value: outcome.value.value,
    };
  } catch (error) {
    if (error instanceof ReusableExtismRuntimeError) {
      return {
        cleanup: "ok",
        error: normalizeRuntimeError(error),
        guestPagesAfter: error.guestPagesAfter,
        guestPagesBefore: error.guestPagesBefore,
        ok: false,
        operationCompleted: false,
        pluginCreated: error.pluginCreated,
        pluginDisposition: error.pluginDisposition,
        pluginReused: error.pluginReused,
      };
    }
    return failedBeforeLease(new CoreAdapterError("plugin.create", "plugin_create_failed"));
  }
}

function failedBeforeLease(error: CoreAdapterError): CoreLifecycleOutcome<never> {
  return {
    cleanup: "ok",
    error,
    guestPagesAfter: null,
    guestPagesBefore: null,
    ok: false,
    operationCompleted: false,
    pluginCreated: false,
    pluginDisposition: "not_used",
    pluginReused: false,
  };
}

function normalizeRuntimeError(error: ReusableExtismRuntimeError): CoreAdapterError {
  if (error.code === "operation_deadline_exceeded") {
    return new CoreAdapterError("operation.invoke", "operation_deadline_exceeded");
  }
  if (error.code === "operation_aborted") {
    return new CoreAdapterError("operation.invoke", "operation_aborted");
  }
  if (error.code === "mutex_queue_full") {
    return new CoreAdapterError("operation.invoke", "operation_queue_full");
  }
  if (error.stage === "plugin.create") {
    return new CoreAdapterError("plugin.create", "plugin_create_failed");
  }
  if (error.stage === "plugin.close") {
    return new CoreAdapterError("plugin.close", "plugin_evict_failed");
  }
  return new CoreAdapterError("operation.invoke", "core_call_failed");
}

async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function timed<T>(
  stage: CoreLifecycleStage,
  operation: () => Promise<T>,
  observeTiming?: (stage: CoreLifecycleStage, durationMs: number) => void,
): Promise<T> {
  const startedAt = performance.now();
  try {
    return await operation();
  } finally {
    observeTiming?.(stage, performance.now() - startedAt);
  }
}
