export const managementSections = [
  "approvers",
  "requesters",
  "passkeys",
] as const;

export type ManagementSection = (typeof managementSections)[number];

export function parseManagementSection(value: unknown): ManagementSection {
  return managementSections.includes(value as ManagementSection)
    ? (value as ManagementSection)
    : "approvers";
}
