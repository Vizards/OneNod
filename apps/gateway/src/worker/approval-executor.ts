import {
  canonicalJsonSha256Base64Url,
  decodeBase64Url,
  sha256Base64Url,
} from "@onenod/protocol";

import {
  sanitizeCatalogEnvelope,
  sanitizeCredentialUseEnvelope,
  sanitizeGatewayError,
  sanitizeItemMetadataEnvelope,
  sanitizeItemMutationEnvelope,
  sanitizeItemReconciliationEnvelope,
  sanitizeSecretMetadataEnvelope,
  sanitizeSecretReadEnvelope,
  sanitizeSshSignEnvelope,
  type CatalogExecutorItem,
  type CredentialUseExecutorResult,
  type ItemMutationExecutorResult,
  type ItemReconciliationExecutorResult,
  type SecretMetadataExecutorResult,
  type SecretReadExecutorResult,
  type SshSignExecutorResult,
} from "./gateway-envelope.js";
import { catalogMetadataCacheKey } from "./approval-projection.js";
import type {
  CatalogMetadataCacheRow,
  RequestRow,
  RequestSecretFieldRow,
} from "./approval-types.js";
import {
  GatewayHttpError,
  safeSshSignatureAlgorithm,
  sanitizeExecutorEnvelope,
} from "./approval-http.js";
import { ExecutorTransportError } from "./executor-transport.js";
import {
  callExecutorService,
  type ExecutorExecutionIdentity,
} from "./executor-service-transport.js";

declare const EXECUTOR_FETCH_TIMEOUT_MS: number;

const CATALOG_METADATA_CACHE_TTL_MS = 2 * 60_000;
const CATALOG_METADATA_CACHE_MAX_ENTRIES = 2_048;
const MAX_EXECUTOR_CONCURRENCY = 4;

export class ApprovalExecutor {
  private readonly catalogMetadataCache = new Map<string, CatalogMetadataCacheRow>();
  private executorInFlight = 0;

  constructor(private readonly env: Env) {}

  async executeCatalog(query: string): Promise<CatalogExecutorItem[]> {
    const trusted = await this.callExecutor("/internal/1password/catalog", {
      query,
    });
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    const items = sanitizeExecutorEnvelope(() =>
      sanitizeCatalogEnvelope(trusted.body, trusted.status),
    );
    this.cacheCatalogMetadata(items);
    return items;
  }

  async executeSecretMetadata(
    itemId: string,
    fieldId: string,
  ): Promise<SecretMetadataExecutorResult> {
    const trusted = await this.callExecutor(
      "/internal/1password/secret/metadata",
      { field_id: fieldId, item_id: itemId },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    const metadata = sanitizeExecutorEnvelope(() =>
      sanitizeSecretMetadataEnvelope(trusted.body, trusted.status, {
        field_id: fieldId,
        item_id: itemId,
      }),
    );
    this.cacheSecretMetadata(metadata);
    return metadata;
  }

  cachedSecretMetadata(
    itemId: string,
    fieldId: string,
    expectedVersion: number,
  ): SecretMetadataExecutorResult | undefined {
    const key = catalogMetadataCacheKey(itemId, fieldId, expectedVersion);
    const row = this.catalogMetadataCache.get(key);
    if (!row || row.cached_at < Date.now() - CATALOG_METADATA_CACHE_TTL_MS) {
      if (row) this.catalogMetadataCache.delete(key);
      return undefined;
    }
    return {
      field_id: row.field_id,
      field_label: row.field_label,
      field_type: row.field_type,
      item_id: row.item_id,
      item_title: row.item_title,
      version: row.version,
    };
  }

  cacheCatalogMetadata(items: CatalogExecutorItem[]): void {
    const cachedAt = Date.now();
    for (const item of items) {
      for (const field of item.fields) {
        this.cacheSecretMetadata(
          {
            field_id: field.field_id,
            field_label: field.label,
            field_type: field.field_type,
            item_id: item.item_id,
            item_title: item.title,
            version: item.version,
          },
          cachedAt,
        );
      }
    }
  }

  cacheSecretMetadata(
    metadata: SecretMetadataExecutorResult,
    cachedAt = Date.now(),
  ): void {
    const key = catalogMetadataCacheKey(
      metadata.item_id,
      metadata.field_id,
      metadata.version,
    );
    this.catalogMetadataCache.delete(key);
    this.catalogMetadataCache.set(key, { ...metadata, cached_at: cachedAt });
    while (this.catalogMetadataCache.size > CATALOG_METADATA_CACHE_MAX_ENTRIES) {
      const oldest = this.catalogMetadataCache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.catalogMetadataCache.delete(oldest);
    }
  }

  invalidateCatalogMetadata(...itemIds: string[]): void {
    const targets = new Set(itemIds);
    for (const [key, metadata] of this.catalogMetadataCache) {
      if (targets.has(metadata.item_id)) this.catalogMetadataCache.delete(key);
    }
  }

  async executeSecretRead(
    row: RequestRow,
  ): Promise<SecretReadExecutorResult> {
    const trusted = await this.callExecutor(
      "/internal/1password/secret/read",
      {
        expected_version: row.expected_version,
        field_id: row.field_id,
        item_id: row.item_id,
      },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeSecretReadEnvelope(trusted.body, trusted.status, {
        field_id: row.field_id,
        field_label: row.field_label,
        field_type: row.field_type,
        item_id: row.item_id,
        item_title: row.item_title,
        version: row.expected_version,
      }),
    );
  }

  async executeCredentialUse(
    row: RequestRow,
    fields: RequestSecretFieldRow[],
  ): Promise<CredentialUseExecutorResult> {
    const trusted = await this.callExecutor(
      "/internal/1password/credential/use",
      {
        expected_version: row.expected_version,
        field_ids: fields.map((field) => field.field_id),
        item_id: row.item_id,
      },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeCredentialUseEnvelope(trusted.body, trusted.status, {
        fields: fields.map((field) => ({
          field_id: field.field_id,
          field_label: field.field_label,
          field_type: field.field_type,
          item_id: row.item_id,
          item_title: row.item_title,
          version: row.expected_version,
        })),
        item_id: row.item_id,
        item_title: row.item_title,
        version: row.expected_version,
      }),
    );
  }

  async executeItemMetadata(itemId: string): Promise<CatalogExecutorItem> {
    const trusted = await this.callExecutor(
      "/internal/1password/item/metadata",
      { item_id: itemId },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeItemMetadataEnvelope(trusted.body, trusted.status, itemId),
    );
  }

  async executeItemMutation(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<ItemMutationExecutorResult> {
    const execution = await this.executorExecutionIdentity(row, body);
    const trusted = await this.callExecutor(
      "/internal/1password/item/mutate",
      body,
      execution,
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeItemMutationEnvelope(
        trusted.body,
        trusted.status,
        row.action === "item.create" ? undefined : row.item_id,
      ),
    );
  }

  async reconcileItemMutation(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<ItemReconciliationExecutorResult> {
    const execution = await this.executorExecutionIdentity(row, body);
    const trusted = await this.callExecutor(
      "/internal/1password/item/reconcile",
      body,
      execution,
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeItemReconciliationEnvelope(
        trusted.body,
        trusted.status,
        row.action === "item.create" ? undefined : row.item_id,
      ),
    );
  }

  async executeSshSign(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<SshSignExecutorResult> {
    const algorithm = safeSshSignatureAlgorithm(row.field_type);
    const trusted = await this.callExecutor(
      "/internal/1password/ssh/sign",
      body,
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    const result = sanitizeExecutorEnvelope(() =>
      sanitizeSshSignEnvelope(trusted.body, trusted.status, {
        algorithm,
        fingerprint: row.field_label,
        item_id: row.item_id,
        version: row.expected_version,
      }),
    );
    const digest = await sha256Base64Url(decodeBase64Url(result.public_key_blob));
    const fingerprint = `SHA256:${digest.replace(/-/gu, "+").replace(/_/gu, "/")}`;
    if (fingerprint !== result.fingerprint) {
      throw new GatewayHttpError("executor_response_invalid", 502);
    }
    return result;
  }

  async callExecutor(
    path: string,
    body: Record<string, unknown>,
    execution?: ExecutorExecutionIdentity,
  ): Promise<{ body: Record<string, unknown>; status: number }> {
    if (!this.env.EXECUTOR_AUTH_TOKEN) {
      throw new GatewayHttpError("executor_not_configured", 503);
    }
    if (!this.env.EXECUTOR_SERVICE) {
      throw new GatewayHttpError("executor_not_configured", 503);
    }
    if (this.executorInFlight >= MAX_EXECUTOR_CONCURRENCY) {
      throw new GatewayHttpError("executor_busy", 429);
    }
    this.executorInFlight += 1;
    try {
      return await callExecutorService({
        authToken: this.env.EXECUTOR_AUTH_TOKEN,
        body,
        ...(execution === undefined ? {} : { execution }),
        path,
        service: this.env.EXECUTOR_SERVICE,
        timeoutMs: EXECUTOR_FETCH_TIMEOUT_MS,
      });
    } catch (error) {
      throw new GatewayHttpError(
        error instanceof ExecutorTransportError && error.failure === "timeout"
          ? "executor_timeout"
          : "executor_unavailable",
        error instanceof ExecutorTransportError && error.failure === "timeout"
          ? 504
          : 502,
      );
    } finally {
      this.executorInFlight -= 1;
    }
  }

  async executorExecutionIdentity(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<ExecutorExecutionIdentity> {
    if (
      row.action !== "item.create" &&
      row.action !== "item.patch" &&
      row.action !== "item.archive"
    ) {
      throw new GatewayHttpError("item_operation_invalid", 400);
    }
    return {
      bodyDigest: await canonicalJsonSha256Base64Url(body),
      requestId: row.id,
    };
  }

}
