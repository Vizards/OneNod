import { buildPushHTTPRequest, type PushSubscription } from "@pushforge/builder";
import { decodeBase64Url, encodeBase64Url } from "@onenod/protocol";

export interface StoredPushSubscription {
  auth: string;
  endpoint: string;
  expirationTime: number | null;
  p256dh: string;
}

export interface ApprovalPushMessage {
  body: string;
  requestId?: string;
  tag: string;
  title: string;
  url: string;
}

export interface VapidKeys {
  privateKey: string | undefined;
  publicKey: string | undefined;
  subject: string | undefined;
}

export interface PushDeliveryResult {
  failureName?: string;
  failureStage?: "payload_build" | "provider_fetch" | "request_build" | "unknown";
  outcome: "delivered" | "gone" | "retry" | "failed";
  status?: number;
}

export function validatePushSubscription(value: unknown): StoredPushSubscription {
  if (!isRecord(value)) throw new Error("push_subscription_invalid");
  const endpoint = value.endpoint;
  const expirationValue = value.expirationTime ?? value.expiration_time ?? null;
  const keys = value.keys;
  if (typeof endpoint !== "string" || endpoint.length > 2_048) {
    throw new Error("push_endpoint_invalid");
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error("push_endpoint_invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    isLocalOrIpHost(url.hostname)
  ) {
    throw new Error("push_endpoint_invalid");
  }
  if (
    expirationValue !== null &&
    (typeof expirationValue !== "number" ||
      !Number.isFinite(expirationValue) ||
      expirationValue < 0)
  ) {
    throw new Error("push_expiration_invalid");
  }
  const expirationTime = expirationValue === null ? null : expirationValue;
  if (!isRecord(keys)) throw new Error("push_keys_invalid");
  const auth = keys.auth;
  const p256dh = keys.p256dh;
  if (!isBase64Url(auth, 8, 128) || !isBase64Url(p256dh, 32, 256)) {
    throw new Error("push_keys_invalid");
  }
  return {
    auth,
    endpoint: url.toString(),
    expirationTime,
    p256dh,
  };
}

export async function deliverWebPush(
  subscription: StoredPushSubscription,
  message: ApprovalPushMessage,
  vapid: VapidKeys,
  send: typeof fetch = fetch,
): Promise<PushDeliveryResult> {
  const data: Record<string, string> = {
    body: message.body,
    tag: message.tag,
    title: message.title,
    url: message.url,
    ...(message.requestId ? { requestId: message.requestId } : {}),
  };
  let request: Awaited<ReturnType<typeof buildPushHTTPRequest>>;
  try {
    request = await buildPushHTTPRequest({
      message: {
        adminContact: requireVapidSubject(vapid.subject),
        payload: data,
        options: {
          topic: pushTopic(message.tag),
          ttl: 120,
          urgency: "high",
        },
      },
      privateJWK: vapidPrivateJwk(vapid),
      subscription: {
        endpoint: subscription.endpoint,
        keys: { auth: subscription.auth, p256dh: subscription.p256dh },
      } satisfies PushSubscription,
    });
  } catch {
    return { failureStage: "payload_build", outcome: "failed" };
  }
  const body = new Uint8Array(request.body);
  const headers = workerSafePushHeaders(request.headers);
  let outboundRequest: Request;
  try {
    outboundRequest = new Request(subscription.endpoint, {
      body: body.buffer,
      headers,
      method: "POST",
      redirect: "manual",
    });
  } catch (error) {
    return {
      failureName: safeFailureName(error),
      failureStage: "request_build",
      outcome: "failed",
    };
  }
  let response: Response;
  try {
    response = await send(outboundRequest);
  } catch (error) {
    return {
      failureName: safeFailureName(error),
      failureStage: "provider_fetch",
      outcome: "retry",
    };
  }
  if (response.status >= 200 && response.status < 300) {
    return { outcome: "delivered", status: response.status };
  }
  if (response.status === 404 || response.status === 410) {
    return { outcome: "gone", status: response.status };
  }
  if (response.status === 408 || response.status === 429 || response.status >= 500) {
    return { outcome: "retry", status: response.status };
  }
  return { outcome: "failed", status: response.status };
}

export function workerSafePushHeaders(
  input: Headers | Record<string, string | undefined>,
): Headers {
  const headers = new Headers();
  const entries = input instanceof Headers ? input.entries() : Object.entries(input);
  for (const [name, value] of entries) {
    // Cloudflare computes Content-Length from the fixed-size ArrayBuffer body.
    // Supplying the payload-generated value makes Workers reject the subrequest
    // before it reaches the push provider.
    if (name.toLowerCase() !== "content-length" && value !== undefined) {
      headers.set(name, value);
    }
  }
  return headers;
}

function vapidPrivateJwk(vapid: VapidKeys): JsonWebKey {
  if (!vapid.privateKey || !vapid.publicKey) {
    throw new Error("vapid_keys_incomplete");
  }
  const publicKey = decodeBase64Url(vapid.publicKey);
  const privateKey = decodeBase64Url(vapid.privateKey);
  if (
    publicKey.byteLength !== 65 ||
    publicKey[0] !== 0x04 ||
    privateKey.byteLength !== 32
  ) {
    throw new Error("vapid_keys_invalid");
  }
  return {
    crv: "P-256",
    d: vapid.privateKey,
    ext: true,
    key_ops: ["sign"],
    kty: "EC",
    x: encodeBase64Url(publicKey.slice(1, 33)),
    y: encodeBase64Url(publicKey.slice(33, 65)),
  };
}

function requireVapidSubject(subject: string | undefined): string {
  if (!subject) throw new Error("vapid_keys_incomplete");
  return subject;
}

function pushTopic(value: string): string {
  return value.replace(/[^A-Za-z0-9_-]/gu, "_").slice(0, 32) || "approval";
}

function isLocalOrIpHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(lower) ||
    lower.includes(":")
  );
}

function isBase64Url(value: unknown, minimum: number, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length >= minimum &&
    value.length <= maximum &&
    /^[A-Za-z0-9_-]+$/u.test(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeFailureName(error: unknown): string {
  if (error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,39}$/u.test(error.name)) {
    return error.name;
  }
  return "UnknownError";
}
