import type { Plugin } from "@extism/extism";
// `nodejs_compat` is enabled only for the pinned SSH parser. Resolve Extism's
// browser build explicitly so that the Node conditional export cannot add
// filesystem/path capabilities to the Worker artifact.
import createPlugin from "../node_modules/@extism/extism/dist/browser/mod.js";

import { normalizeAccountHost } from "./account";
import { createOnePasswordHostFunctions } from "./host-functions";
import {
  type ActivePluginLease,
  ReusableExtismRuntime,
} from "./reusable-extism-runtime";

const MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_VAR_BYTES = 2 * 1024 * 1024;
const MAX_WASM_PAGES = 1536;
export const OPERATION_TIMEOUT_MS = 25_000;

export { normalizeAccountHost } from "./account";

export function createOnePasswordRuntime(
  coreModule: WebAssembly.Module,
  baseFetch: typeof fetch = fetch,
): ReusableExtismRuntime {
  return new ReusableExtismRuntime((accountHost, generation, getActiveLease) =>
    createOnePasswordPlugin(
      coreModule,
      accountHost,
      generation,
      getActiveLease,
      baseFetch,
    ),
  );
}

export async function createOnePasswordPlugin(
  coreModule: WebAssembly.Module,
  accountHost: string,
  generation: number,
  getActiveLease: () => ActivePluginLease | undefined,
  baseFetch: typeof fetch = fetch,
): Promise<Plugin> {
  const normalizedHost = normalizeAccountHost(accountHost);
  return createPlugin(coreModule, {
    allowedHosts: [`*.${normalizedHost.split(".").slice(-2).join(".")}`],
    fetch: createRestrictedFetch(
      normalizedHost,
      generation,
      getActiveLease,
      baseFetch,
    ),
    functions: createOnePasswordHostFunctions(),
    logLevel: "silent",
    memory: {
      maxHttpResponseBytes: MAX_HTTP_RESPONSE_BYTES,
      maxPages: MAX_WASM_PAGES,
      maxVarBytes: MAX_VAR_BYTES,
    },
    runInWorker: false,
    timeoutMs: null,
    useWasi: false,
  });
}

export function createRestrictedFetch(
  accountHost: string,
  generation: number,
  getActiveLease: () => ActivePluginLease | undefined,
  baseFetch: typeof fetch = fetch,
): typeof fetch {
  const normalizedHost = normalizeAccountHost(accountHost);
  const regionSuffix = normalizedHost.split(".").slice(-2).join(".");
  return async (input, init) => {
    const lease = requireActiveLease(getActiveLease, generation);
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.protocol !== "https:" || !hostMatchesRegion(url.hostname, regionSuffix)) {
      throw new Error("upstream_host_not_allowed");
    }

    const remainingMs = lease.deadlineAt - Date.now();
    if (remainingMs <= 0) {
      throw new DOMException("operation deadline exceeded", "TimeoutError");
    }

    const controller = new AbortController();
    const timeout = setTimeout(
      () =>
        controller.abort(
          new DOMException("operation deadline exceeded", "TimeoutError"),
        ),
      remainingMs,
    );
    const sourceSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    const abortFromSource = (): void =>
      controller.abort(
        sourceSignal?.reason instanceof Error
          ? sourceSignal.reason
          : new DOMException("upstream request aborted", "AbortError"),
      );
    if (sourceSignal?.aborted) {
      abortFromSource();
    } else {
      sourceSignal?.addEventListener("abort", abortFromSource, { once: true });
    }
    const abortFromLease = (): void =>
      controller.abort(
        lease.signal.reason instanceof Error
          ? lease.signal.reason
          : new DOMException("operation aborted", "AbortError"),
      );
    if (lease.signal.aborted) {
      abortFromLease();
    } else {
      lease.signal.addEventListener("abort", abortFromLease, { once: true });
    }
    try {
      controller.signal.throwIfAborted();
      lease.observeUpstreamRequest?.();
      const response = await baseFetch(input, {
        ...init,
        redirect: "manual",
        signal: controller.signal,
      });
      lease.observeUpstreamResponse?.(response.status);
      if (response.status === 429) {
        lease.upstreamRateLimited = true;
      }
      const body = await readResponseBody(
        response,
        controller.signal,
        () => requireActiveLease(getActiveLease, generation),
      );
      requireActiveLease(getActiveLease, generation);
      controller.signal.throwIfAborted();
      const headers = new Headers(response.headers);
      headers.delete("content-encoding");
      headers.delete("content-length");
      headers.delete("transfer-encoding");
      return new Response(bodyForStatus(response.status, body), {
        headers,
        status: response.status,
        statusText: response.statusText,
      });
    } finally {
      clearTimeout(timeout);
      sourceSignal?.removeEventListener("abort", abortFromSource);
      lease.signal.removeEventListener("abort", abortFromLease);
    }
  };
}

async function readResponseBody(
  response: Response,
  signal: AbortSignal,
  requireLease: () => ActivePluginLease,
): Promise<ArrayBuffer> {
  const reader = response.body?.getReader();
  if (!reader) return new ArrayBuffer(0);

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      requireLease();
      signal.throwIfAborted();
      const { done, value } = await readWithSignal(reader, signal);
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_HTTP_RESPONSE_BYTES) {
        throw new RangeError("upstream_response_too_large");
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }

  const output = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output.buffer;
}

function readWithSignal(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    void reader.read().then(resolve, reject).finally(() => {
      signal.removeEventListener("abort", onAbort);
    });
  });
}

function bodyForStatus(status: number, body: ArrayBuffer): BodyInit | null {
  return status === 101 || status === 204 || status === 205 || status === 304
    ? null
    : body;
}

function requireActiveLease(
  getActiveLease: () => ActivePluginLease | undefined,
  generation: number,
): ActivePluginLease {
  const lease = getActiveLease();
  if (!lease) throw new Error("plugin_fetch_outside_active_lease");
  if (lease.generation !== generation) throw new Error("plugin_fetch_lease_mismatch");
  if (lease.aborted) throw new DOMException("operation aborted", "AbortError");
  return lease;
}

function hostMatchesRegion(hostname: string, regionSuffix: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === regionSuffix || normalized.endsWith(`.${regionSuffix}`);
}
