import {
  EXECUTOR_PROTOCOL_HEADER,
  EXECUTOR_PROTOCOL_VERSION,
} from "@onenod/protocol";

const MAX_EXECUTOR_RESPONSE_BYTES = 64 * 1024;

export type ExecutorTransportFailure =
  | "timeout"
  | "unavailable"
  | "untrusted_response";

export class ExecutorTransportError extends Error {
  override readonly name = "ExecutorTransportError";

  constructor(readonly failure: ExecutorTransportFailure) {
    super(failure);
  }
}

export interface TrustedExecutorResponse {
  body: Record<string, unknown>;
  status: number;
}

export async function readTrustedExecutorResponse(
  operation: Promise<Response>,
  timeoutMs: number,
): Promise<TrustedExecutorResponse> {
  const deadline = Date.now() + timeoutMs;
  let response: Response;
  try {
    response = await withDeadline(operation, remainingTime(deadline));
  } catch (error) {
    throw new ExecutorTransportError(isTimeoutError(error) ? "timeout" : "unavailable");
  }

  if (
    response.headers.get(EXECUTOR_PROTOCOL_HEADER) !== EXECUTOR_PROTOCOL_VERSION ||
    !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }

  const declaredLengthHeader = response.headers.get("content-length");
  if (declaredLengthHeader !== null) {
    const declaredLength = Number(declaredLengthHeader);
    if (
      !Number.isInteger(declaredLength) ||
      declaredLength < 0 ||
      declaredLength > MAX_EXECUTOR_RESPONSE_BYTES
    ) {
      throw new ExecutorTransportError("untrusted_response");
    }
  }

  let bytes: Uint8Array;
  try {
    bytes = await readBoundedBody(response.body, deadline);
  } catch (error) {
    if (error instanceof ExecutorTransportError) throw error;
    throw new ExecutorTransportError(isTimeoutError(error) ? "timeout" : "unavailable");
  }

  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new ExecutorTransportError("untrusted_response");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ExecutorTransportError("untrusted_response");
  }

  return {
    body: body as Record<string, unknown>,
    status: response.status,
  };
}

async function readBoundedBody(
  body: ReadableStream<Uint8Array> | null,
  deadline: number,
): Promise<Uint8Array> {
  if (!body) return new Uint8Array();

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await withDeadline(
        reader.read(),
        remainingTime(deadline),
      );
      if (done) break;
      size += value.byteLength;
      if (size > MAX_EXECUTOR_RESPONSE_BYTES) {
        await reader.cancel();
        throw new ExecutorTransportError("untrusted_response");
      }
      chunks.push(value);
    }
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // Ignore cancellation failures; the caller returns a stable transport error.
    }
    throw error;
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export async function withDeadline<T>(
  operation: Promise<T>,
  timeoutMs: number,
): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive finite number");
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new DOMException("Timed out", "TimeoutError")), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function remainingTime(deadline: number): number {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    throw new DOMException("Timed out", "TimeoutError");
  }
  return remaining;
}

function isTimeoutError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "AbortError" || error.name === "TimeoutError")
  );
}
