import type { CatalogExecutorItem } from "./gateway-envelope.js";
import type { TrustedCatalogMetadataRow } from "./approval-types.js";

const MAX_TRUSTED_CATALOG_FIELDS = 4_096;

/**
 * Stores only the sanitized, non-secret projection returned by Executor.
 * Version is part of the key; replacing an item version cannot silently reuse
 * labels or field identities observed for an older item revision.
 */
export function storeTrustedCatalogItems(
  storage: DurableObjectStorage,
  items: readonly CatalogExecutorItem[],
  observedAt = Date.now(),
): void {
  storage.transactionSync(() => {
    for (const item of items) {
      storage.sql.exec(
        `DELETE FROM trusted_catalog_metadata
         WHERE item_id = ? AND item_version != ?`,
        item.item_id,
        item.version,
      );
      for (const field of item.fields) {
        storage.sql.exec(
          `INSERT INTO trusted_catalog_metadata
            (item_id, item_version, item_title, field_id, field_label,
             field_type, observed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(item_id, item_version, field_id) DO UPDATE SET
             item_title = excluded.item_title,
             field_label = excluded.field_label,
             field_type = excluded.field_type,
             observed_at = excluded.observed_at`,
          item.item_id,
          item.version,
          item.title,
          field.field_id,
          field.label,
          field.field_type,
          observedAt,
        );
      }
    }
    storage.sql.exec(
      `DELETE FROM trusted_catalog_metadata WHERE rowid IN (
         SELECT rowid FROM trusted_catalog_metadata
         ORDER BY observed_at DESC, item_id DESC, item_version DESC, field_id DESC
         LIMIT -1 OFFSET ?
       )`,
      MAX_TRUSTED_CATALOG_FIELDS,
    );
  });
}

export function trustedCatalogFields(
  sql: SqlStorage,
  itemId: string,
  itemVersion: number,
  fieldIds: readonly string[],
): TrustedCatalogMetadataRow[] {
  if (fieldIds.length === 0) return [];
  const placeholders = fieldIds.map(() => "?").join(", ");
  return sql.exec<Record<string, SqlStorageValue>>(
    `SELECT item_id, item_version, item_title, field_id, field_label,
            field_type, observed_at
     FROM trusted_catalog_metadata
     WHERE item_id = ? AND item_version = ? AND field_id IN (${placeholders})`,
    itemId,
    itemVersion,
    ...fieldIds,
  ).toArray() as unknown as TrustedCatalogMetadataRow[];
}
