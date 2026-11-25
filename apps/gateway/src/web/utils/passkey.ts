import {
  startAuthentication as beginAuthentication,
  startRegistration as beginRegistration,
} from "@simplewebauthn/browser";

// SimpleWebAuthn cancels an existing ceremony when another begins. Keep a
// second action from interrupting an authenticator sheet that is already open.
let ceremonyActive = false;

async function runCeremony<T>(action: () => Promise<T>): Promise<T> {
  if (ceremonyActive) {
    throw new Error("Another passkey verification is already in progress.");
  }
  ceremonyActive = true;
  try {
    return await action();
  } finally {
    ceremonyActive = false;
  }
}

export function startAuthentication(
  options: Parameters<typeof beginAuthentication>[0],
): ReturnType<typeof beginAuthentication> {
  return runCeremony(() => beginAuthentication(options));
}

export function startRegistration(
  options: Parameters<typeof beginRegistration>[0],
): ReturnType<typeof beginRegistration> {
  return runCeremony(() => beginRegistration(options));
}
