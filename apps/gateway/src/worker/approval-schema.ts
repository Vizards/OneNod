import {
  DEFAULT_PASSKEY_LABEL,
  LEGACY_DEFAULT_PASSKEY_LABEL,
} from "../passkey-identity.js";
import { legacyBearerlessSshBridgeExpiresAt } from "./legacy-consume-bridge.js";
import { RETENTION_SWEEP_INTERVAL_MS } from "./retention-policy.js";

export interface ApprovalSchemaSql {
  exec(
    query: string,
    ...bindings: unknown[]
  ): { toArray(): Record<string, unknown>[] };
}

export interface ApprovalSchemaStorage {
  transactionSync<T>(closure: () => T): T;
}

export function initializeApprovalSchema(
  storage: ApprovalSchemaStorage,
  sql: ApprovalSchemaSql,
): void {
  new ApprovalSchema(storage, sql).initialize();
}

class ApprovalSchema {
  constructor(
    private readonly storage: ApprovalSchemaStorage,
    private readonly sql: ApprovalSchemaSql,
  ) {}

  private first<T>(
    query: string,
    ...bindings: unknown[]
  ): T | undefined {
    return this.sql.exec(query, ...bindings).toArray()[0] as T | undefined;
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql.exec(query, ...bindings).toArray() as T[];
  }

  initialize(): void {
    this.assertDestructiveMigrationsSafe();
    for (const statement of [
      `CREATE TABLE IF NOT EXISTS human_credentials (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL,
        transports TEXT NOT NULL,
        device_type TEXT NOT NULL,
        backed_up INTEGER NOT NULL,
        label TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        challenge TEXT NOT NULL,
        target_id TEXT,
        decision TEXT,
        payload TEXT,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS human_sessions (
        token_hash TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        device_id TEXT,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        expires_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS human_devices (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        platform TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        revoked_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS human_device_enrollments (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        label TEXT NOT NULL,
        platform TEXT NOT NULL,
        public_key TEXT NOT NULL,
        public_key_fingerprint TEXT NOT NULL,
        requested_by_credential_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        terminal_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS push_subscriptions (
        device_id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL UNIQUE,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        expiration_time INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_success_at INTEGER,
        failure_count INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS bootstrap_sessions (
        id TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        armed_until INTEGER,
        consumed_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_bootstrap_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        used_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS requester_enrollments (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        display_name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        public_key_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        terminal_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS requesters (
        device_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS requester_nonces (
        device_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, nonce)
      )`,
      `CREATE TABLE IF NOT EXISTS legacy_bearerless_ssh_requesters (
        device_id TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_runtime_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        locked INTEGER NOT NULL,
        lock_generation INTEGER NOT NULL,
        changed_at INTEGER NOT NULL,
        changed_by TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS ssh_authorization_grants (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        agent_instance_public_key TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        scope_kind TEXT NOT NULL,
        client_application TEXT NOT NULL,
        application_principal_scheme TEXT NOT NULL,
        application_signing_identifier TEXT NOT NULL,
        application_team_identifier TEXT,
        application_signer_name TEXT,
        item_id TEXT NOT NULL,
        item_title TEXT NOT NULL,
        item_version INTEGER NOT NULL,
        fingerprint TEXT NOT NULL,
        duration TEXT NOT NULL,
        lock_generation INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        authorized_by_credential_id TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS secret_authorization_grants (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        client_application TEXT NOT NULL,
        application_principal_scheme TEXT NOT NULL,
        application_signing_identifier TEXT NOT NULL,
        application_team_identifier TEXT,
        application_signer_name TEXT,
        item_id TEXT NOT NULL,
        item_title TEXT NOT NULL,
        field_id TEXT NOT NULL,
        field_label TEXT NOT NULL,
        field_type TEXT NOT NULL,
        item_version INTEGER NOT NULL,
        duration TEXT NOT NULL,
        lock_generation INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        authorized_by_credential_id TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        requester_name TEXT NOT NULL,
        action TEXT NOT NULL,
        item_id TEXT NOT NULL,
        field_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        client_application TEXT NOT NULL,
        client_source TEXT NOT NULL,
        application_assurance TEXT NOT NULL,
        application_principal_scheme TEXT,
        application_principal_id TEXT,
        application_signing_identifier TEXT,
        application_team_identifier TEXT,
        application_signer_name TEXT,
        application_scope_id TEXT,
        secret_grant_id TEXT,
        ssh_agent_instance_public_key TEXT,
        ssh_scope_id TEXT,
        ssh_scope_kind TEXT,
        ssh_grant_id TEXT,
        legacy_ssh_signed_consume INTEGER NOT NULL DEFAULT 0
          CHECK (legacy_ssh_signed_consume IN (0, 1)),
        item_title TEXT NOT NULL,
        field_label TEXT NOT NULL,
        field_type TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        body_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER,
        authorized_until INTEGER,
        execution_started_at INTEGER,
        consumed_at INTEGER,
        error_code TEXT,
        UNIQUE (requester_device_id, idempotency_key)
      )`,
      `CREATE TABLE IF NOT EXISTS request_operations (
        request_id TEXT PRIMARY KEY,
        operation_summary TEXT NOT NULL,
        payload_aad TEXT,
        payload_ciphertext TEXT,
        payload_digest TEXT,
        payload_iv TEXT,
        reconcile_state TEXT,
        reconcile_attempt_count INTEGER NOT NULL DEFAULT 0,
        reconcile_attempted_at INTEGER,
        result_item_id TEXT,
        result_version INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS request_activity (
        request_id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        terminal_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER,
        consumed_at INTEGER,
        item_title TEXT NOT NULL,
        field_label TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        requester_name TEXT NOT NULL,
        client_application TEXT NOT NULL,
        client_source TEXT NOT NULL,
        application_assurance TEXT NOT NULL DEFAULT 'unverified',
        application_principal_scheme TEXT,
        application_principal_id TEXT,
        application_signing_identifier TEXT,
        application_team_identifier TEXT,
        application_signer_name TEXT,
        error_code TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_crypto_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        master_key_fingerprint TEXT NOT NULL,
        initialized_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        request_id TEXT,
        actor_id TEXT,
        created_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_maintenance_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        next_retention_at INTEGER NOT NULL,
        retention_active INTEGER NOT NULL DEFAULT 0,
        retention_started_at INTEGER,
        activity_backfill_done INTEGER NOT NULL DEFAULT 0,
        activity_backfill_cursor_created_at INTEGER,
        activity_backfill_cursor_id TEXT,
        request_trim_done INTEGER NOT NULL DEFAULT 0,
        audit_trim_done INTEGER NOT NULL DEFAULT 0,
        activity_trim_done INTEGER NOT NULL DEFAULT 0,
        request_cutoff_created_at INTEGER,
        request_cutoff_id TEXT,
        audit_cutoff_created_at INTEGER,
        audit_cutoff_id INTEGER,
        activity_cutoff_created_at INTEGER,
        activity_cutoff_id TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      )`,
      `CREATE INDEX IF NOT EXISTS idx_requests_created_at
       ON requests(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_requests_transition_deadline
       ON requests(status, expires_at, authorized_until, execution_started_at)`,
      `CREATE INDEX IF NOT EXISTS idx_request_activity_cursor
       ON request_activity(created_at DESC, request_id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_request_activity_terminal
       ON request_activity(terminal_at, request_id)`,
      `CREATE INDEX IF NOT EXISTS idx_enrollments_status
       ON requester_enrollments(status, created_at)`,
      `CREATE INDEX IF NOT EXISTS idx_human_device_enrollments_status
       ON human_device_enrollments(status, created_at)`,
      `CREATE INDEX IF NOT EXISTS idx_gateway_audit_retention
       ON gateway_audit(created_at, id)`,
      `CREATE INDEX IF NOT EXISTS idx_human_devices_revoked
       ON human_devices(revoked_at, id)`,
      `CREATE INDEX IF NOT EXISTS idx_requester_nonces_expiry
       ON requester_nonces(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_human_sessions_expiry
       ON human_sessions(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry
       ON webauthn_challenges(expires_at, used_at)`,
      `CREATE INDEX IF NOT EXISTS idx_ssh_authorization_grants_lookup
       ON ssh_authorization_grants(
         requester_device_id, agent_instance_public_key, scope_id, item_id,
         item_version, fingerprint, revoked_at
       )`,
      `CREATE INDEX IF NOT EXISTS idx_secret_authorization_grants_lookup
       ON secret_authorization_grants(
         requester_device_id, scope_id, item_id, field_id, item_version,
         revoked_at
       )`,
    ]) {
      this.sql.exec(statement);
    }
    this.ensureColumn("human_credentials", "last_used_at", "INTEGER");
    this.ensureColumn("human_sessions", "device_id", "TEXT");
    this.ensureColumn("human_sessions", "last_seen_at", "INTEGER");
    this.ensureColumn(
      "request_operations",
      "reconcile_attempt_count",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn("request_operations", "reconcile_attempted_at", "INTEGER");
    this.ensureColumn("requests", "ssh_agent_instance_public_key", "TEXT");
    this.ensureColumn(
      "requests",
      "application_assurance",
      "TEXT NOT NULL DEFAULT 'unverified'",
    );
    this.ensureColumn("requests", "application_principal_scheme", "TEXT");
    this.ensureColumn("requests", "application_principal_id", "TEXT");
    this.ensureColumn("requests", "application_signing_identifier", "TEXT");
    this.ensureColumn("requests", "application_team_identifier", "TEXT");
    this.ensureColumn("requests", "application_signer_name", "TEXT");
    this.ensureColumn("requests", "application_scope_id", "TEXT");
    this.ensureColumn("requests", "secret_grant_id", "TEXT");
    this.ensureColumn("requests", "ssh_scope_id", "TEXT");
    this.ensureColumn("requests", "ssh_scope_kind", "TEXT");
    this.ensureColumn("requests", "ssh_grant_id", "TEXT");
    this.ensureColumn(
      "requests",
      "legacy_ssh_signed_consume",
      "INTEGER NOT NULL DEFAULT 0 CHECK (legacy_ssh_signed_consume IN (0, 1))",
    );
    this.ensureColumn(
      "request_activity",
      "application_assurance",
      "TEXT NOT NULL DEFAULT 'unverified'",
    );
    this.ensureColumn("request_activity", "application_principal_scheme", "TEXT");
    this.ensureColumn("request_activity", "application_principal_id", "TEXT");
    this.ensureColumn("request_activity", "application_signing_identifier", "TEXT");
    this.ensureColumn("request_activity", "application_team_identifier", "TEXT");
    this.ensureColumn("request_activity", "application_signer_name", "TEXT");
    this.ensureColumn(
      "ssh_authorization_grants",
      "item_title",
      "TEXT NOT NULL DEFAULT 'SSH key'",
    );
    this.ensureColumn(
      "ssh_authorization_grants",
      "client_application",
      "TEXT NOT NULL DEFAULT 'Unknown local client'",
    );
    this.ensureColumn(
      "ssh_authorization_grants",
      "application_principal_scheme",
      "TEXT NOT NULL DEFAULT 'legacy-v1'",
    );
    this.ensureColumn(
      "ssh_authorization_grants",
      "application_signing_identifier",
      "TEXT NOT NULL DEFAULT 'unknown'",
    );
    this.ensureColumn("ssh_authorization_grants", "application_team_identifier", "TEXT");
    this.ensureColumn("ssh_authorization_grants", "application_signer_name", "TEXT");
    this.ensureColumn(
      "secret_authorization_grants",
      "application_principal_scheme",
      "TEXT NOT NULL DEFAULT 'legacy-v1'",
    );
    this.ensureColumn(
      "secret_authorization_grants",
      "application_signing_identifier",
      "TEXT NOT NULL DEFAULT 'unknown'",
    );
    this.ensureColumn("secret_authorization_grants", "application_team_identifier", "TEXT");
    this.ensureColumn("secret_authorization_grants", "application_signer_name", "TEXT");
    this.sql.exec(
      `UPDATE ssh_authorization_grants SET revoked_at = ?
       WHERE scope_kind != 'application' AND revoked_at IS NULL`,
      Date.now(),
    );
    this.migrateRequestClientObservation();
    this.ensureColumn("requester_enrollments", "terminal_at", "INTEGER");
    this.ensureColumn("human_device_enrollments", "terminal_at", "INTEGER");
    this.ensureColumn(
      "gateway_maintenance_state",
      "retention_active",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn("gateway_maintenance_state", "retention_started_at", "INTEGER");
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_backfill_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_backfill_cursor_created_at",
      "INTEGER",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_backfill_cursor_id",
      "TEXT",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "request_trim_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "audit_trim_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_trim_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "request_cutoff_created_at",
      "INTEGER",
    );
    this.ensureColumn("gateway_maintenance_state", "request_cutoff_id", "TEXT");
    this.ensureColumn(
      "gateway_maintenance_state",
      "audit_cutoff_created_at",
      "INTEGER",
    );
    this.ensureColumn("gateway_maintenance_state", "audit_cutoff_id", "INTEGER");
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_cutoff_created_at",
      "INTEGER",
    );
    this.ensureColumn("gateway_maintenance_state", "activity_cutoff_id", "TEXT");
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_requester_enrollment_retention
       ON requester_enrollments(status, expires_at, terminal_at)`,
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_human_device_enrollment_retention
       ON human_device_enrollments(status, expires_at, terminal_at)`,
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_requests_transition_deadline
       ON requests(status, expires_at, authorized_until, execution_started_at)`,
    );
    this.sql.exec(
      `UPDATE requester_enrollments SET terminal_at = created_at
       WHERE status != 'pending' AND terminal_at IS NULL`,
    );
    this.sql.exec(
      `UPDATE human_device_enrollments SET terminal_at = created_at
       WHERE status != 'pending' AND terminal_at IS NULL`,
    );
    // Retire the former second-device approval ceremony. A fresh registered
    // Passkey now authorizes device registration directly; old pending rows
    // are migration-only receipts and become eligible for bounded cleanup.
    this.sql.exec(
      `UPDATE human_device_enrollments
       SET status = 'rejected', terminal_at = COALESCE(terminal_at, ?)
       WHERE status = 'pending'`,
      Date.now(),
    );
    // Migrate away from the old correctness-independent persistent cache.
    this.sql.exec(`DROP TABLE IF EXISTS catalog_metadata_cache`);
    this.sql.exec(
      `INSERT OR IGNORE INTO gateway_runtime_state
        (singleton, locked, lock_generation, changed_at, changed_by)
       VALUES (1, 0, 0, ?, 'system')`,
      Date.now(),
    );
    this.sql.exec(
      `INSERT OR IGNORE INTO gateway_maintenance_state
        (singleton, next_retention_at) VALUES (1, ?)`,
      Date.now() + RETENTION_SWEEP_INTERVAL_MS,
    );
    this.sql.exec(
      `INSERT OR IGNORE INTO gateway_schema_migrations (version, applied_at)
       VALUES (1, ?)`,
      Date.now(),
    );
    this.migrateLegacyDefaultPasskeyLabel();
    this.migrateStableApplicationAuthorizationScopes();
    this.migrateVerifiedApplicationAuthorizationScopes();
    this.migrateLegacyBearerlessSshRequesters();
  }

  /**
   * Some upgrades intentionally retire old authority or replace old state.
   * Detect those concrete mutations before CREATE/ALTER/UPDATE can touch the
   * database, and let active requests drain first. Fresh and already-current
   * databases never enter this gate.
   */
  private assertDestructiveMigrationsSafe(): void {
    if (
      !this.tableExists("requests") ||
      !this.destructiveMigrationPending()
    ) {
      return;
    }
    const now = Date.now();
    const active = this.first<{ id: string }>(
      `SELECT id FROM requests
       WHERE status IN ('executing', 'unknown')
          OR (status = 'pending' AND expires_at > ?)
          OR (status = 'approved' AND COALESCE(authorized_until, expires_at) > ?)
       LIMIT 1`,
      now,
      now,
    );
    if (active) {
      throw new Error("destructive_migration_blocked_by_active_request");
    }
  }

  private destructiveMigrationPending(): boolean {
    const requestColumns = this.rows<{ name: string }>(
      "PRAGMA table_info(requests)",
    );
    if (!requestColumns.some((column) => column.name === "client_application")) {
      return true;
    }
    if (this.tableExists("catalog_metadata_cache")) return true;
    if (
      this.tableExists("human_device_enrollments") &&
      this.first<{ id: string }>(
        "SELECT id FROM human_device_enrollments WHERE status = 'pending' LIMIT 1",
      )
    ) {
      return true;
    }

    const migrationVersions = this.tableExists("gateway_schema_migrations")
      ? new Set(
        this.rows<{ version: number }>(
          "SELECT version FROM gateway_schema_migrations",
        ).map((row) => row.version),
      )
      : new Set<number>();
    if (this.tableExists("ssh_authorization_grants")) {
      const activeSshGrant = this.first<{ id: string }>(
        "SELECT id FROM ssh_authorization_grants WHERE revoked_at IS NULL LIMIT 1",
      );
      if (activeSshGrant && (!migrationVersions.has(3) || !migrationVersions.has(4))) {
        return true;
      }
      const legacyScope = this.first<{ id: string }>(
        `SELECT id FROM ssh_authorization_grants
         WHERE revoked_at IS NULL AND scope_kind != 'application' LIMIT 1`,
      );
      if (legacyScope) return true;
    }
    if (
      !migrationVersions.has(4) &&
      this.tableExists("secret_authorization_grants") &&
      this.first<{ id: string }>(
        "SELECT id FROM secret_authorization_grants WHERE revoked_at IS NULL LIMIT 1",
      )
    ) {
      return true;
    }
    return false;
  }

  private tableExists(table: string): boolean {
    return Boolean(this.first<{ name: string }>(
      "SELECT name FROM sqlite_schema WHERE type = 'table' AND name = ?",
      table,
    ));
  }

  private migrateLegacyDefaultPasskeyLabel(): void {
    const migrated = this.first<{ version: number }>(
      `SELECT version FROM gateway_schema_migrations WHERE version = 2`,
    );
    if (migrated) return;

    this.storage.transactionSync(() => {
      this.sql.exec(
        `UPDATE human_credentials SET label = ?
         WHERE id = (
           SELECT id FROM human_credentials
           WHERE label = ? AND revoked_at IS NULL
           ORDER BY created_at ASC LIMIT 1
         )`,
        DEFAULT_PASSKEY_LABEL,
        LEGACY_DEFAULT_PASSKEY_LABEL,
      );
      this.sql.exec(
        `INSERT INTO gateway_schema_migrations (version, applied_at)
         VALUES (2, ?)`,
        Date.now(),
      );
    });
  }

  private migrateStableApplicationAuthorizationScopes(): void {
    const migrated = this.first<{ version: number }>(
      `SELECT version FROM gateway_schema_migrations WHERE version = 3`,
    );
    if (migrated) return;

    this.storage.transactionSync(() => {
      // Earlier clients derived both "application" and "terminal-session"
      // scopes from short-lived PIDs. Those values cannot safely authorize the
      // stable application identity introduced by this schema version.
      this.sql.exec(
        `UPDATE ssh_authorization_grants SET revoked_at = ?
         WHERE revoked_at IS NULL`,
        Date.now(),
      );
      this.sql.exec(
        `INSERT INTO gateway_schema_migrations (version, applied_at)
         VALUES (3, ?)`,
        Date.now(),
      );
    });
  }

  private migrateVerifiedApplicationAuthorizationScopes(): void {
    const migrated = this.first<{ version: number }>(
      `SELECT version FROM gateway_schema_migrations WHERE version = 4`,
    );
    if (migrated) return;

    this.storage.transactionSync(() => {
      // A legacy scope was derived from process names, PIDs, or unverified
      // bundle metadata. It must never authorize the code-signature principal
      // introduced by application attestation v1.
      const now = Date.now();
      this.sql.exec(
        `UPDATE ssh_authorization_grants SET revoked_at = ?
         WHERE revoked_at IS NULL`,
        now,
      );
      this.sql.exec(
        `UPDATE secret_authorization_grants SET revoked_at = ?
         WHERE revoked_at IS NULL`,
        now,
      );
      this.sql.exec(
        `INSERT INTO gateway_schema_migrations (version, applied_at)
         VALUES (4, ?)`,
        now,
      );
    });
  }

  private migrateLegacyBearerlessSshRequesters(): void {
    const migrated = this.first<{ version: number }>(
      `SELECT version FROM gateway_schema_migrations WHERE version = 5`,
    );
    if (migrated) return;

    const now = Date.now();
    this.storage.transactionSync(() => {
      // This is a temporary dogfood bridge. Only requesters that already
      // existed when the bridge was deployed may create an eligible request;
      // newly enrolled protocol-2 requesters are never added to this table.
      this.sql.exec(
        `INSERT OR IGNORE INTO legacy_bearerless_ssh_requesters
          (device_id, expires_at)
         SELECT device_id, ? FROM requesters WHERE revoked_at IS NULL`,
        legacyBearerlessSshBridgeExpiresAt(now),
      );
      this.sql.exec(
        `INSERT INTO gateway_schema_migrations (version, applied_at)
         VALUES (5, ?)`,
        now,
      );
    });
  }

  private migrateRequestClientObservation(): void {
    const columns = this.rows<{ name: string }>("PRAGMA table_info(requests)");
    if (columns.some((column) => column.name === "client_application")) return;
    const now = Date.now();
    const active = this.first<{ id: string }>(
      `SELECT id FROM requests
       WHERE status IN ('executing', 'unknown')
          OR (status = 'pending' AND expires_at > ?)
          OR (status = 'approved' AND COALESCE(authorized_until, expires_at) > ?)
       LIMIT 1`,
      now,
      now,
    );
    if (active) {
      throw new Error("request_schema_migration_blocked_by_active_request");
    }

    this.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM request_operations");
      this.sql.exec("DROP TABLE IF EXISTS requests_client_observation");
      this.sql.exec(`CREATE TABLE requests_client_observation (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        requester_name TEXT NOT NULL,
        action TEXT NOT NULL,
        item_id TEXT NOT NULL,
        field_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        client_application TEXT NOT NULL,
        client_source TEXT NOT NULL,
        application_assurance TEXT NOT NULL DEFAULT 'unverified',
        application_principal_scheme TEXT,
        application_principal_id TEXT,
        application_signing_identifier TEXT,
        application_team_identifier TEXT,
        application_signer_name TEXT,
        application_scope_id TEXT,
        secret_grant_id TEXT,
        ssh_agent_instance_public_key TEXT,
        ssh_scope_id TEXT,
        ssh_scope_kind TEXT,
        ssh_grant_id TEXT,
        legacy_ssh_signed_consume INTEGER NOT NULL DEFAULT 0
          CHECK (legacy_ssh_signed_consume IN (0, 1)),
        item_title TEXT NOT NULL,
        field_label TEXT NOT NULL,
        field_type TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        body_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER,
        authorized_until INTEGER,
        execution_started_at INTEGER,
        consumed_at INTEGER,
        error_code TEXT,
        UNIQUE (requester_device_id, idempotency_key)
      )`);
      this.sql.exec("DROP TABLE requests");
      this.sql.exec("ALTER TABLE requests_client_observation RENAME TO requests");
      this.sql.exec(
        "CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at DESC)",
      );
      this.sql.exec(
        `INSERT INTO gateway_audit (event, request_id, actor_id, created_at)
         VALUES ('request_schema_replaced', NULL, 'system', ?)`,
        Date.now(),
      );
    });
  }

  private ensureColumn(table: string, column: string, declaration: string): void {
    const existing = this.rows<{ name: string }>(`PRAGMA table_info(${table})`);
    if (existing.some((entry) => entry.name === column)) return;
    this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${declaration}`);
  }
}
