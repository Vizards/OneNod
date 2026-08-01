import {
  type TrustedExecutorResponse,
  readTrustedExecutorResponse,
} from "./executor-transport.js";

const EXECUTOR_SERVICE_ORIGIN = "http://executor.internal";
export const EXECUTOR_BODY_DIGEST_HEADER = "x-1pr-body-digest";
export const EXECUTOR_REQUEST_ID_HEADER = "x-1pr-request-id";

const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BODY_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export interface ExecutorServiceBinding {
  fetch(request: Request): Promise<Response>;
}

export interface ExecutorExecutionIdentity {
  bodyDigest: string;
  requestId: string;
}

export async function callExecutorService(input: {
  authToken: string;
  body: Record<string, unknown>;
  execution?: ExecutorExecutionIdentity;
  path: string;
  service: ExecutorServiceBinding;
  timeoutMs: number;
}): Promise<TrustedExecutorResponse> {
  if (
    !input.path.startsWith("/") ||
    input.path.startsWith("//") ||
    /[?#\r\n]/u.test(input.path)
  ) {
    throw new TypeError("executor service path must be absolute and contain no query or fragment");
  }

  if (
    input.execution !== undefined &&
    (!REQUEST_ID_PATTERN.test(input.execution.requestId) ||
      !BODY_DIGEST_PATTERN.test(input.execution.bodyDigest))
  ) {
    throw new TypeError("executor execution identity is invalid");
  }

  const headers = new Headers({
    authorization: `Bearer ${input.authToken}`,
    "content-type": "application/json",
  });
  if (input.execution !== undefined) {
    headers.set(EXECUTOR_REQUEST_ID_HEADER, input.execution.requestId);
    headers.set(EXECUTOR_BODY_DIGEST_HEADER, input.execution.bodyDigest);
  }

  const request = new Request(`${EXECUTOR_SERVICE_ORIGIN}${input.path}`, {
    body: JSON.stringify(input.body),
    headers,
    method: "POST",
  });

  return readTrustedExecutorResponse(
    Promise.resolve().then(() => input.service.fetch(request)),
    input.timeoutMs,
  );
}
