import { ExecutionJournalError } from "./execution-journal";
import { ExecutorRequestError } from "./executor-request-error";
import { GatewayOperationError } from "./onepassword-raw-gateway";
import { isSqliteFullError } from "./storage-policy";

export type ExecutorFailureKind =
  | "known-operation"
  | "request-validation"
  | "storage-pressure"
  | "unexpected-internal";

export interface ClassifiedExecutorFailure {
  error: GatewayOperationError;
  errorName: string;
  kind: ExecutorFailureKind;
}

export function classifyExecutorFailure(
  error: unknown,
  path: string,
): ClassifiedExecutorFailure {
  if (error instanceof GatewayOperationError) {
    return {
      error,
      errorName: safeExecutorErrorName(error),
      kind: "known-operation",
    };
  }
  if (
    (error instanceof ExecutionJournalError &&
      error.code === "journal_storage_pressure") ||
    isSqliteFullError(error)
  ) {
    return {
      error: new GatewayOperationError("executor_storage_pressure", 507),
      errorName: safeExecutorErrorName(error),
      kind: "storage-pressure",
    };
  }
  if (error instanceof ExecutorRequestError) {
    return {
      error: new GatewayOperationError(invalidRequestCode(path), 400),
      errorName: safeExecutorErrorName(error),
      kind: "request-validation",
    };
  }
  return {
    error: new GatewayOperationError("executor_internal_error", 503),
    errorName: safeExecutorErrorName(error),
    kind: "unexpected-internal",
  };
}

export function safeExecutorErrorName(error: unknown): string {
  return error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,39}$/u.test(error.name)
    ? error.name
    : "UnknownError";
}

function invalidRequestCode(
  path: string,
): "catalog_query_invalid" | "item_operation_invalid" | "ssh_sign_request_invalid" {
  if (path === "/internal/1password/catalog") return "catalog_query_invalid";
  if (path === "/internal/1password/ssh/sign") return "ssh_sign_request_invalid";
  return "item_operation_invalid";
}
