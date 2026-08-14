import type {
  ApplicationIdentityColumns,
} from "./approval-types.js";

export interface ApprovedApplicationIdentitySql {
  exec(query: string, ...bindings: unknown[]): unknown;
}

export function recordApprovedApplicationIdentity(
  sql: ApprovedApplicationIdentitySql,
  identity: ApplicationIdentityColumns,
  approvedAt: number,
): boolean {
  if (
    identity.application_assurance !== "verified-code-signature" ||
    !identity.application_principal_scheme ||
    !identity.application_principal_id ||
    !identity.application_signing_identifier
  ) {
    return false;
  }
  sql.exec(
    `INSERT INTO approved_application_identities
      (principal_scheme, principal_id, signing_identifier,
       team_identifier, signer_name, first_approved_at,
       last_approved_at, approval_count)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1)
     ON CONFLICT(principal_scheme, principal_id) DO UPDATE SET
       signing_identifier = excluded.signing_identifier,
       team_identifier = excluded.team_identifier,
       signer_name = excluded.signer_name,
       last_approved_at = excluded.last_approved_at,
       approval_count = approved_application_identities.approval_count + 1`,
    identity.application_principal_scheme,
    identity.application_principal_id,
    identity.application_signing_identifier,
    identity.application_team_identifier,
    identity.application_signer_name,
    approvedAt,
    approvedAt,
  );
  return true;
}

export function projectApplicationRecognition(
  row: Pick<ApplicationIdentityColumns, "application_assurance"> & {
    application_approved_before?: number;
  },
): "approved-before" | "first-approval" | "unverified" {
  if (row.application_assurance !== "verified-code-signature") {
    return "unverified";
  }
  return row.application_approved_before === 1
    ? "approved-before"
    : "first-approval";
}
