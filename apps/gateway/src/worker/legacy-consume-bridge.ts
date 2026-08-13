import { pollingTokensMatch } from "./request-polling.js";

const LEGACY_BEARERLESS_SSH_BRIDGE_WINDOW_MS = 24 * 60 * 60_000;

export function legacyBearerlessSshBridgeExpiresAt(now: number): number {
  return now + LEGACY_BEARERLESS_SSH_BRIDGE_WINDOW_MS;
}

/**
 * Protocol 1 did not send client.identity. Call this only after the complete
 * request body and requester signature have passed their normal validation.
 */
export function legacySshSignedConsumeEligible(body: unknown): boolean {
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  const input = body as Record<string, unknown>;
  if (input.action !== "ssh.sign") return false;
  if (!input.client || typeof input.client !== "object" || Array.isArray(input.client)) {
    return false;
  }
  return !Object.hasOwn(input.client, "identity");
}

export function requestPollingAuthorizationAccepted(input: {
  action: string;
  authorizationHeader: string | null;
  expectedToken: string;
  legacySshSignedConsume: number;
  secretGrantId: string | null;
  sshGrantId: string | null;
}): boolean {
  if (input.authorizationHeader !== null) {
    const match = /^Bearer ([A-Za-z0-9_-]{43})$/u.exec(
      input.authorizationHeader,
    );
    return pollingTokensMatch(match?.[1], input.expectedToken);
  }
  return input.action === "ssh.sign" &&
    input.legacySshSignedConsume === 1 &&
    input.secretGrantId === null &&
    input.sshGrantId === null;
}
