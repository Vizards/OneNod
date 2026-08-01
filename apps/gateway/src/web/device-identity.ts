const DATABASE_NAME = "onepassword-remote-device";
const STORE_NAME = "identity";
const IDENTITY_KEY = "current";

export interface DeviceIdentity {
  deviceId: string;
  publicKey: JsonWebKey;
  sign(message: string): Promise<string>;
}

interface StoredIdentity {
  deviceId: string;
  privateKey: CryptoKey;
  publicKey: JsonWebKey;
}

export async function getOrCreateDeviceIdentity(): Promise<DeviceIdentity> {
  const database = await openDatabase();
  const existing = await readIdentity(database);
  if (existing) return exposeIdentity(existing);

  const generated = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey("jwk", generated.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", generated.publicKey);
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const stored: StoredIdentity = {
    deviceId: crypto.randomUUID(),
    privateKey,
    publicKey: normalizePublicJwk(publicJwk),
  };
  await writeIdentity(database, stored);
  return exposeIdentity(stored);
}

export function suggestedDeviceDetails(): { label: string; platform: string } {
  const standalone = window.matchMedia("(display-mode: standalone)").matches;
  const agent = navigator.userAgent;
  if (/iPhone/iu.test(agent)) {
    return { label: standalone ? "iPhone PWA" : "iPhone Safari", platform: "iphone" };
  }
  if (/iPad/iu.test(agent)) {
    return { label: standalone ? "iPad PWA" : "iPad Safari", platform: "ipad" };
  }
  if (/Macintosh/iu.test(agent)) {
    return { label: standalone ? "Mac PWA" : "Mac browser", platform: "mac" };
  }
  return { label: standalone ? "PWA device" : "Browser device", platform: "other" };
}

export function deviceProofMessage(
  purpose: string,
  challengeId: string,
  challenge: string,
  deviceId: string,
): string {
  return ["1p-human-device-v1", purpose, challengeId, challenge, deviceId].join("\n");
}

function exposeIdentity(stored: StoredIdentity): DeviceIdentity {
  return {
    deviceId: stored.deviceId,
    publicKey: stored.publicKey,
    async sign(message: string): Promise<string> {
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        stored.privateKey,
        new TextEncoder().encode(message),
      );
      return encodeBase64Url(new Uint8Array(signature));
    },
  };
}

function normalizePublicJwk(value: JsonWebKey): JsonWebKey {
  if (value.kty !== "EC" || value.crv !== "P-256" || !value.x || !value.y) {
    throw new Error("The browser generated an unsupported device public key.");
  }
  return { crv: value.crv, kty: value.kty, x: value.x, y: value.y };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open device credential storage."));
  });
}

function readIdentity(database: IDBDatabase): Promise<StoredIdentity | undefined> {
  return new Promise((resolve, reject) => {
    const request = database.transaction(STORE_NAME).objectStore(STORE_NAME).get(IDENTITY_KEY);
    request.onsuccess = () => resolve(request.result as StoredIdentity | undefined);
    request.onerror = () => reject(request.error ?? new Error("Unable to read the device credential."));
  });
}

function writeIdentity(database: IDBDatabase, identity: StoredIdentity): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(identity, IDENTITY_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Unable to save the device credential."));
  });
}

function encodeBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
