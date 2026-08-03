export const DEFAULT_PASSKEY_LABEL = "Primary passkey";
export const LEGACY_DEFAULT_PASSKEY_LABEL = "Mac passkey";
export const PASSKEY_RP_NAME = "OneNod";
export const PASSKEY_USER_DISPLAY_NAME = "OneNod owner";
export const PASSKEY_USER_NAME = "owner";

// Keep the existing opaque user handle stable so previously registered
// credentials and newly registered credentials represent the same owner.
export const PASSKEY_USER_HANDLE = "onenod-approver";

export function passkeyPortabilityLabel(
  deviceType: string,
  backedUp: boolean,
): "Device-bound" | "Sync-capable" | "Synced" | "Unknown" {
  if (deviceType === "multiDevice") {
    return backedUp ? "Synced" : "Sync-capable";
  }
  if (deviceType === "singleDevice") return "Device-bound";
  return "Unknown";
}
