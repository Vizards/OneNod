export function normalizeAccountHost(accountHost: string): string {
  const normalized = accountHost.trim().toLowerCase().replace(/^https:\/\//, "");
  if (
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.1password\.(com|ca|eu)$/.test(
      normalized,
    )
  ) {
    throw new Error("unsupported_1password_account_host");
  }
  return normalized;
}
