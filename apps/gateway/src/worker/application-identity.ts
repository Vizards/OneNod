export interface StoredApplicationIdentityRow {
  application_assurance: string;
  application_principal_id: string | null;
  application_principal_scheme: string | null;
  application_signer_name: string | null;
  application_signing_identifier: string | null;
  application_team_identifier: string | null;
}

export function projectStoredApplicationIdentity(
  row: StoredApplicationIdentityRow,
) {
  if (
    row.application_assurance === "verified-code-signature" &&
    row.application_principal_scheme === "macos-designated-requirement-v1" &&
    row.application_principal_id &&
    row.application_signing_identifier
  ) {
    return {
      assurance: "verified-code-signature" as const,
      platform: "macos" as const,
      principal_id: row.application_principal_id,
      principal_scheme: "macos-designated-requirement-v1" as const,
      ...(row.application_signer_name
        ? { signer_name: row.application_signer_name }
        : {}),
      signing_identifier: row.application_signing_identifier,
      ...(row.application_team_identifier
        ? { team_identifier: row.application_team_identifier }
        : {}),
    };
  }
  return { assurance: "unverified" as const, platform: "unsupported" as const };
}
