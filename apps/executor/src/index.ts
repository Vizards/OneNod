import { DurableObject } from "cloudflare:workers";

import coreModule from "./core.wasm";
import { tokensMatch } from "./auth";
import {
  ExecutionJournal,
  ExecutionJournalError,
  SqliteExecutionJournalStore,
} from "./execution-journal";
import {
  EXECUTOR_PROTOCOL_HEADER,
  EXECUTOR_PROTOCOL_VERSION,
  INTERNAL_ONEPASSWORD_PATHS,
  executeJournaledMutation,
  executeJournaledReconciliation,
  parseCatalogRequest,
  parseHealthRequest,
  parseItemMetadataRequest,
  parseMutationRequest,
  parseSecretMetadataRequest,
  parseSecretReadRequest,
  parseSshSignRequest,
  readExecutionIdentity,
  readJsonObject,
} from "./internal-onepassword-api";
import {
  CoreAdapterError,
  type OnePasswordCoreClient,
  runWithOnePasswordClient,
} from "./onepassword-core";
import {
  GatewayOperationError,
  executeCatalog,
  executeItemArchive,
  executeItemCreate,
  executeItemMetadata,
  executeItemPatch,
  executeSecretRead,
  executeSecretReadMetadata,
  executeSshSign,
  reconcileItemArchive,
  reconcileItemCreate,
  reconcileItemPatch,
} from "./onepassword-raw-gateway";
import { OPERATION_TIMEOUT_MS, createOnePasswordRuntime } from "./runtime";
import { EXECUTOR_RELEASE } from "./release";
import {
  executorStoragePressure,
  isSqliteFullError,
} from "./storage-policy";

interface Env {
  EXECUTOR_AUTH_TOKEN?: string;
  ONEPASSWORD_EXECUTOR: DurableObjectNamespace<OnePasswordExecutor>;
  OP_ACCOUNT: string;
  OP_SERVICE_ACCOUNT_TOKEN?: string;
  OP_VAULT_ID: string;
}

const JSON_HEADERS = {
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
} as const;

const ONEPASSWORD_EXECUTOR_INSTANCE = "onepassword-primary";
export const EXECUTOR_VERSION_PATH = "/internal/version";
const ACCEPTED_GATEWAY_PROTOCOL_MIN = 1;
const ACCEPTED_GATEWAY_PROTOCOL_MAX = 1;
const EXECUTOR_STATE_SCHEMA = 1;

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === EXECUTOR_VERSION_PATH) {
      if (request.method !== "POST") {
        return executorJson({ ok: false, error: "not_found" }, 404);
      }
      const authorizationFailure = await authorizeExecutor(request, env);
      if (authorizationFailure) return authorizationFailure;
      try {
        parseHealthRequest(await readJsonObject(request, 1_024));
      } catch (error) {
        return executorGatewayError(error, url.pathname);
      }
      return executorJson(executorVersion());
    }

    if (INTERNAL_ONEPASSWORD_PATHS.has(url.pathname)) {
      if (request.method !== "POST") {
        return executorJson({ ok: false, error: "not_found" }, 404);
      }
      const authorizationFailure = await authorizeExecutor(request, env);
      if (authorizationFailure) return authorizationFailure;
      return env.ONEPASSWORD_EXECUTOR.getByName(ONEPASSWORD_EXECUTOR_INSTANCE).fetch(
        request,
      );
    }

    return executorJson({ ok: false, error: "not_found" }, 404);
  },
} satisfies ExportedHandler<Env>;

function executorVersion(): {
  accepted_gateway_protocol: { max: number; min: number };
  ok: true;
  release_channel: typeof EXECUTOR_RELEASE.channel;
  release_tag: string;
  release_version: string;
  service: "onenod-executor";
  source_commit: string;
  state_schema: number;
} {
  return {
    accepted_gateway_protocol: {
      max: ACCEPTED_GATEWAY_PROTOCOL_MAX,
      min: ACCEPTED_GATEWAY_PROTOCOL_MIN,
    },
    ok: true,
    release_channel: EXECUTOR_RELEASE.channel,
    release_tag: EXECUTOR_RELEASE.tag,
    release_version: EXECUTOR_RELEASE.version,
    service: "onenod-executor",
    source_commit: EXECUTOR_RELEASE.sourceCommit,
    state_schema: EXECUTOR_STATE_SCHEMA,
  };
}

export class OnePasswordExecutor extends DurableObject<Env> {
  private readonly journal: ExecutionJournal;
  private readonly runtime = createOnePasswordRuntime(coreModule);
  private storageWarningReported = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.journal = new ExecutionJournal(
      new SqliteExecutionJournalStore(ctx.storage),
      { beforeInsert: () => this.assertJournalGrowthAllowed() },
    );
    this.journal.initialize();
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (INTERNAL_ONEPASSWORD_PATHS.has(url.pathname)) {
      return this.fetchInternal(request, url);
    }
    return executorJson({ ok: false, error: "not_found" }, 404);
  }

  private async fetchInternal(request: Request, url: URL): Promise<Response> {
    if (request.method !== "POST") {
      return executorJson({ ok: false, error: "not_found" }, 404);
    }
    const authorizationFailure = await authorizeExecutor(request, this.env);
    if (authorizationFailure) return authorizationFailure;
    if (url.pathname === "/internal/health") {
      try {
        parseHealthRequest(await readJsonObject(request, 1_024));
      } catch (error) {
        return executorGatewayError(error, url.pathname);
      }
      return executorJson({
        configured: {
          executorAuthToken: Boolean(this.env.EXECUTOR_AUTH_TOKEN),
          onePasswordServiceAccount: Boolean(this.env.OP_SERVICE_ACCOUNT_TOKEN),
          onePasswordVault: Boolean(this.env.OP_VAULT_ID),
        },
        ...executorVersion(),
        runtime: "cloudflare-worker-sqlite-do",
        storage: {
          database_size_bytes: this.ctx.storage.sql.databaseSize,
          pressure: executorStoragePressure(this.ctx.storage.sql.databaseSize),
        },
      });
    }
    if (!this.env.OP_SERVICE_ACCOUNT_TOKEN) {
      return executorJson(
        { ok: false, error: "onepassword_operation_failed" },
        502,
      );
    }

    try {
      if (url.pathname === "/internal/1password/catalog") {
        const query = parseCatalogRequest(await readJsonObject(request, 4_096));
        const items = await this.runGatewayOperation(request.signal, (client) =>
          executeCatalog({ client, query, vaultId: this.env.OP_VAULT_ID }),
        );
        return executorJson({ ok: true, items });
      }

      if (url.pathname === "/internal/1password/secret/metadata") {
        const target = parseSecretMetadataRequest(
          await readJsonObject(request, 4_096),
        );
        const metadata = await this.runGatewayOperation(request.signal, (client) =>
          executeSecretReadMetadata({
            client,
            fieldId: target.fieldId,
            itemId: target.itemId,
            vaultId: this.env.OP_VAULT_ID,
          }),
        );
        return executorJson({ ok: true, ...metadata });
      }

      if (url.pathname === "/internal/1password/secret/read") {
        const target = parseSecretReadRequest(await readJsonObject(request, 4_096));
        const result = await this.runGatewayOperation(request.signal, (client) =>
          executeSecretRead({
            client,
            expectedVersion: target.expectedVersion,
            fieldId: target.fieldId,
            itemId: target.itemId,
            vaultId: this.env.OP_VAULT_ID,
          }),
        );
        return executorJson({ ok: true, ...result });
      }

      if (url.pathname === "/internal/1password/item/metadata") {
        const itemId = parseItemMetadataRequest(
          await readJsonObject(request, 4_096),
        );
        const item = await this.runGatewayOperation(request.signal, (client) =>
          executeItemMetadata({ client, itemId, vaultId: this.env.OP_VAULT_ID }),
        );
        return executorJson({ item, ok: true });
      }

      if (url.pathname === "/internal/1password/ssh/sign") {
        const target = parseSshSignRequest(
          await readJsonObject(request, 96 * 1_024),
        );
        const result = await this.runGatewayOperation(request.signal, (client) =>
          executeSshSign({
            client,
            data: target.data,
            expectedFingerprint: target.expectedFingerprint,
            expectedVersion: target.expectedVersion,
            itemId: target.itemId,
            requestedAlgorithm: target.requestedAlgorithm,
            vaultId: this.env.OP_VAULT_ID,
          }),
        );
        return executorJson({ ok: true, ...result });
      }

      const body = await readJsonObject(request, 64 * 1_024);
      const mutation = parseMutationRequest(body);
      const identity = await readExecutionIdentity(
        request,
        body,
        mutation.action,
      );
      if (url.pathname === "/internal/1password/item/mutate") {
        const result = await executeJournaledMutation({
          identity,
          invoke: () =>
            this.runGatewayOperation(
              request.signal,
              (client) => this.executeMutation(client, mutation),
              true,
            ),
          journal: this.journal,
        });
        return executorJson({ ok: true, ...result });
      }

      const result = await executeJournaledReconciliation({
        identity,
        invoke: () =>
          this.runGatewayOperation(request.signal, (client) =>
            this.reconcileMutation(client, mutation),
          ),
        ...(mutation.action === "item.create" ? {} : { itemId: mutation.itemId }),
        journal: this.journal,
      });
      return executorJson({ ok: true, ...result });
    } catch (error) {
      return executorGatewayError(error, url.pathname);
    }
  }

  private assertJournalGrowthAllowed(): void {
    const databaseSize = this.ctx.storage.sql.databaseSize;
    const pressure = executorStoragePressure(databaseSize);
    if (pressure === "critical") {
      throw new ExecutionJournalError("journal_storage_pressure");
    }
    if (pressure === "warning" && !this.storageWarningReported) {
      this.storageWarningReported = true;
      console.warn(
        JSON.stringify({
          databaseSize,
          event: "executor_storage_pressure",
          level: "warning",
        }),
      );
    }
  }

  private executeMutation(
    client: OnePasswordCoreClient,
    mutation: ReturnType<typeof parseMutationRequest>,
  ) {
    switch (mutation.action) {
      case "item.create":
        return executeItemCreate({
          category: mutation.category,
          client,
          fields: mutation.fields,
          requestId: mutation.requestId,
          title: mutation.title,
          vaultId: this.env.OP_VAULT_ID,
        });
      case "item.patch":
        return executeItemPatch({
          client,
          expectedVersion: mutation.expectedVersion,
          itemId: mutation.itemId,
          operations: mutation.operations,
          vaultId: this.env.OP_VAULT_ID,
        });
      case "item.archive":
        return executeItemArchive({
          client,
          expectedVersion: mutation.expectedVersion,
          itemId: mutation.itemId,
          vaultId: this.env.OP_VAULT_ID,
        });
    }
  }

  private reconcileMutation(
    client: OnePasswordCoreClient,
    mutation: ReturnType<typeof parseMutationRequest>,
  ) {
    switch (mutation.action) {
      case "item.create":
        return reconcileItemCreate({
          client,
          requestId: mutation.requestId,
          vaultId: this.env.OP_VAULT_ID,
        });
      case "item.patch":
        return reconcileItemPatch({
          client,
          expectedVersion: mutation.expectedVersion,
          itemId: mutation.itemId,
          operations: mutation.operations,
          vaultId: this.env.OP_VAULT_ID,
        });
      case "item.archive":
        return reconcileItemArchive({
          client,
          expectedVersion: mutation.expectedVersion,
          itemId: mutation.itemId,
          vaultId: this.env.OP_VAULT_ID,
        });
    }
  }

  private async runGatewayOperation<T>(
    signal: AbortSignal,
    operation: (client: OnePasswordCoreClient) => Promise<T>,
    mutation = false,
  ): Promise<T> {
    let operationEntered = false;
    const lifecycle = await runWithOnePasswordClient(
      this.runtime,
      {
        accountHost: this.env.OP_ACCOUNT,
        deadlineAt: Date.now() + OPERATION_TIMEOUT_MS,
        serviceAccountToken: this.env.OP_SERVICE_ACCOUNT_TOKEN!,
        signal,
      },
      (client) => {
        operationEntered = true;
        return operation(client);
      },
    );
    if (lifecycle.ok) return lifecycle.value;
    if (lifecycle.operationCompleted) {
      console.error(
        JSON.stringify({
          event: "executor_gateway_cleanup_failed",
          cleanup: lifecycle.cleanup,
        }),
      );
      return lifecycle.value;
    }
    if (lifecycle.error instanceof GatewayOperationError) {
      throw lifecycle.error;
    }
    const runtimeFailure =
      lifecycle.error instanceof CoreAdapterError
        ? {
            errorCode: lifecycle.error.code,
            stage: lifecycle.error.stage,
          }
        : {
            errorCode: "unexpected_runtime_failure",
            stage: "unknown",
          };
    console.error(
      JSON.stringify({
        event: "executor_runtime_operation_failed",
        ...runtimeFailure,
        pluginCreated: lifecycle.pluginCreated,
        pluginDisposition: lifecycle.pluginDisposition,
        pluginReused: lifecycle.pluginReused,
      }),
    );
    const timedOut =
      lifecycle.error instanceof CoreAdapterError &&
      (lifecycle.error.code === "operation_aborted" ||
        lifecycle.error.code === "operation_deadline_exceeded");
    if (mutation && operationEntered) {
      throw new GatewayOperationError(
        "onepassword_write_outcome_unknown",
        timedOut ? 504 : 502,
      );
    }
    throw new GatewayOperationError(
      timedOut ? "onepassword_timeout" : "onepassword_operation_failed",
      timedOut ? 504 : 502,
    );
  }

}

async function authorizeExecutor(
  request: Request,
  env: Env,
): Promise<Response | undefined> {
  if (!env.EXECUTOR_AUTH_TOKEN) {
    return executorJson({ ok: false, error: "unauthorized" }, 401);
  }
  const bearer = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!(await tokensMatch(bearer, env.EXECUTOR_AUTH_TOKEN))) {
    return executorJson({ ok: false, error: "unauthorized" }, 401);
  }
}

function executorGatewayError(error: unknown, path: string): Response {
  let classified: GatewayOperationError;
  if (error instanceof GatewayOperationError) {
    classified = error;
  } else if (
    (error instanceof ExecutionJournalError &&
      error.code === "journal_storage_pressure") ||
    isSqliteFullError(error)
  ) {
    classified = new GatewayOperationError("executor_storage_pressure", 507);
  } else {
    classified = new GatewayOperationError(
      path === "/internal/1password/catalog"
        ? "catalog_query_invalid"
        : path === "/internal/1password/ssh/sign"
          ? "ssh_sign_request_invalid"
          : "item_operation_invalid",
      400,
    );
  }
  console.error(
    JSON.stringify({
      errorCode: classified.code,
      event: "executor_gateway_operation_failed",
      path,
    }),
  );
  return executorJson({ error: classified.code, ok: false }, classified.status);
}

function executorJson(body: unknown, status = 200): Response {
  const headers = new Headers(JSON_HEADERS);
  headers.set(EXECUTOR_PROTOCOL_HEADER, EXECUTOR_PROTOCOL_VERSION);
  return new Response(JSON.stringify(body), { headers, status });
}
