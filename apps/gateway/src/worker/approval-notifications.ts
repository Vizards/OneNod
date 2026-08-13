import { GatewayHttpError, iso, json, readJsonObject } from "./approval-http.js";
import type {
  EventSocketAttachment,
  PushSubscriptionRow,
} from "./approval-types.js";
import { HumanAccess } from "./human-access.js";
import {
  deliverWebPush,
  validatePushSubscription,
  type ApprovalPushMessage,
  type PushDeliveryResult,
  type StoredPushSubscription,
} from "./web-push.js";

const HUMAN_EVENT_SOCKET_TAG = "human-events";
const MAX_PUSH_FANOUT = 16;
const MAX_PUSH_CONCURRENCY = 4;
const PUSH_FAILURE_DELETE_THRESHOLD = 5;

export interface ApprovalNotificationCallbacks {
  audit(event: string, requestId?: string, actorId?: string): void;
}

/**
 * Owns the human event channel and best-effort Web Push delivery.
 *
 * Push never participates in the authoritative request transaction: a request
 * remains visible through polling and the event stream if delivery fails.
 */
export class ApprovalNotifications {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly human: HumanAccess,
    private readonly callbacks: ApprovalNotificationCallbacks,
  ) {}

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private first<T>(query: string, ...bindings: unknown[]): T | undefined {
    return this.rows<T>(query, ...bindings)[0];
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql
      .exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray() as unknown as T[];
  }

  async humanEvents(request: Request): Promise<Response> {
    this.human.requireExpectedOrigin(request);
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      throw new GatewayHttpError("websocket_upgrade_required", 426);
    }
    const session = await this.human.requireHumanSession(request);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const attachment: EventSocketAttachment = {
      credentialId: session.credential_id,
      deviceId: session.device_id!,
      expiresAt: session.expires_at,
      sessionHash: session.token_hash,
    };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server, [HUMAN_EVENT_SOCKET_TAG]);
    server.send(
      JSON.stringify({
        at: iso(Date.now()),
        event_id: crypto.randomUUID(),
        type: "ready",
      }),
    );
    return new Response(null, { status: 101, webSocket: client });
  }

  async pushConfig(request: Request): Promise<Response> {
    const session = await this.human.requireHumanSession(request);
    const enabled = Boolean(
      this.first<{ device_id: string }>(
        `SELECT device_id FROM push_subscriptions WHERE device_id = ?`,
        session.device_id,
      ),
    );
    return json({
      configured: Boolean(
        this.env.VAPID_PUBLIC_KEY &&
          this.env.VAPID_PRIVATE_KEY &&
          this.env.VAPID_SUBJECT,
      ),
      enabled,
      public_key: this.env.VAPID_PUBLIC_KEY ?? undefined,
    });
  }

  async putPushSubscription(request: Request): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    let subscription: StoredPushSubscription;
    try {
      subscription = validatePushSubscription(await readJsonObject(request));
    } catch (error) {
      throw new GatewayHttpError(
        error instanceof Error
          ? error.message
          : "push_subscription_invalid",
        400,
      );
    }
    if (
      !this.env.VAPID_PUBLIC_KEY ||
      !this.env.VAPID_PRIVATE_KEY ||
      !this.env.VAPID_SUBJECT
    ) {
      throw new GatewayHttpError("push_not_configured", 503);
    }
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO push_subscriptions
        (device_id, endpoint, p256dh, auth, expiration_time, created_at,
         updated_at, last_success_at, failure_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0)
       ON CONFLICT(device_id) DO UPDATE SET
         endpoint = excluded.endpoint,
         p256dh = excluded.p256dh,
         auth = excluded.auth,
         expiration_time = excluded.expiration_time,
         updated_at = excluded.updated_at,
         failure_count = 0`,
      session.device_id,
      subscription.endpoint,
      subscription.p256dh,
      subscription.auth,
      subscription.expirationTime,
      now,
      now,
    );
    this.callbacks.audit(
      "push_subscription_enabled",
      undefined,
      session.device_id!,
    );
    this.broadcastHumanEvent("management.changed", session.device_id!);
    return json({ enabled: true, ok: true });
  }

  async deletePushSubscription(request: Request): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    await readJsonObject(request);
    this.sql.exec(
      `DELETE FROM push_subscriptions WHERE device_id = ?`,
      session.device_id,
    );
    this.callbacks.audit(
      "push_subscription_disabled",
      undefined,
      session.device_id!,
    );
    this.broadcastHumanEvent("management.changed", session.device_id!);
    return json({ enabled: false, ok: true });
  }

  webSocketMessage(
    socket: WebSocket,
    message: string | ArrayBuffer,
  ): void {
    const attachment =
      socket.deserializeAttachment() as EventSocketAttachment | null;
    if (
      !attachment ||
      attachment.expiresAt <= Date.now() ||
      !this.isActiveEventSession(attachment)
    ) {
      this.safeCloseSocket(socket, 4401, "session_expired");
      return;
    }
    if (message === "ping") {
      try {
        socket.send(JSON.stringify({ at: iso(Date.now()), type: "pong" }));
      } catch {
        this.safeCloseSocket(socket, 1011, "send_failed");
      }
      return;
    }
    this.safeCloseSocket(socket, 4400, "unsupported_message");
  }

  broadcastHumanEvent(type: string, entityId?: string): void {
    const message = JSON.stringify({
      at: iso(Date.now()),
      ...(entityId ? { entity_id: entityId } : {}),
      event_id: crypto.randomUUID(),
      type,
    });
    try {
      for (const socket of this.ctx.getWebSockets(HUMAN_EVENT_SOCKET_TAG)) {
        try {
          const attachment =
            socket.deserializeAttachment() as EventSocketAttachment | null;
          if (!attachment || !this.isActiveEventSession(attachment)) {
            this.safeCloseSocket(socket, 4401, "session_expired");
            continue;
          }
          socket.send(message);
        } catch {
          this.safeCloseSocket(socket, 1011, "send_failed");
        }
      }
    } catch {
      console.error(JSON.stringify({ event: "human_event_broadcast_failed" }));
    }
  }

  closeDeviceSockets(deviceId: string): void {
    for (const socket of this.ctx.getWebSockets(HUMAN_EVENT_SOCKET_TAG)) {
      const attachment =
        socket.deserializeAttachment() as EventSocketAttachment | null;
      if (attachment?.deviceId === deviceId) {
        this.safeCloseSocket(socket, 4403, "device_revoked");
      }
    }
  }

  closeCredentialSockets(credentialId: string): void {
    for (const socket of this.ctx.getWebSockets(HUMAN_EVENT_SOCKET_TAG)) {
      const attachment =
        socket.deserializeAttachment() as EventSocketAttachment | null;
      if (attachment?.credentialId === credentialId) {
        this.safeCloseSocket(socket, 4403, "credential_revoked");
      }
    }
  }

  safeCloseSocket(socket: WebSocket, code: number, reason: string): void {
    try {
      socket.close(code, reason);
    } catch {
      // The peer may complete the closing handshake while sockets are listed.
    }
  }

  queueApprovalPush(message: ApprovalPushMessage): void {
    if (
      !this.env.VAPID_PUBLIC_KEY ||
      !this.env.VAPID_PRIVATE_KEY ||
      !this.env.VAPID_SUBJECT
    ) {
      console.warn(
        JSON.stringify({
          event: "approval_push_skipped",
          reason: "configuration_missing",
        }),
      );
      return;
    }
    try {
      const subscriptions = this.rows<PushSubscriptionRow>(
        `SELECT p.device_id, p.endpoint, p.p256dh, p.auth, p.expiration_time,
                p.failure_count
         FROM push_subscriptions p
         JOIN human_devices d ON d.id = p.device_id AND d.revoked_at IS NULL
         ORDER BY p.updated_at DESC, p.device_id
         LIMIT ?`,
        MAX_PUSH_FANOUT,
      );
      if (subscriptions.length === 0) {
        console.warn(
          JSON.stringify({
            event: "approval_push_skipped",
            reason: "no_subscription",
          }),
        );
        return;
      }
      console.log(
        JSON.stringify({
          event: "approval_push_queued",
          subscriptionCount: subscriptions.length,
        }),
      );
      this.ctx.waitUntil(
        this.deliverPushFanout(subscriptions, message)
          .then(() => undefined)
          .catch(() => {
            console.error(
              JSON.stringify({ event: "approval_push_fanout_failed" }),
            );
          }),
      );
    } catch {
      // Push is best effort and cannot roll back the authoritative mutation.
      console.error(JSON.stringify({ event: "approval_push_queue_failed" }));
    }
  }

  private isActiveEventSession(attachment: EventSocketAttachment): boolean {
    return Boolean(
      this.first<{ token_hash: string }>(
        `SELECT s.token_hash FROM human_sessions s
         JOIN human_devices d ON d.id = s.device_id AND d.revoked_at IS NULL
         JOIN human_credentials c ON c.id = s.credential_id AND c.revoked_at IS NULL
         WHERE s.token_hash = ? AND s.device_id = ? AND s.expires_at > ?`,
        attachment.sessionHash,
        attachment.deviceId,
        Date.now(),
      ),
    );
  }

  private async deliverPushFanout(
    subscriptions: PushSubscriptionRow[],
    message: ApprovalPushMessage,
  ): Promise<void> {
    let nextIndex = 0;
    const deliverNext = async (): Promise<void> => {
      while (nextIndex < subscriptions.length) {
        const subscription = subscriptions[nextIndex];
        nextIndex += 1;
        if (subscription) {
          await this.deliverPushToDevice(subscription, message);
        }
      }
    };
    await Promise.all(
      Array.from(
        { length: Math.min(MAX_PUSH_CONCURRENCY, subscriptions.length) },
        deliverNext,
      ),
    );
  }

  private async deliverPushToDevice(
    row: PushSubscriptionRow,
    message: ApprovalPushMessage,
  ): Promise<void> {
    if (
      this.human.gatewayRuntimeState().locked === 1 &&
      (message.requestId || message.tag.startsWith("requester-"))
    ) {
      console.log(
        JSON.stringify({
          event: "approval_push_skipped",
          reason: "gateway_locked",
        }),
      );
      return;
    }
    if (message.requestId) {
      const current = this.first<{ status: string }>(
        `SELECT status FROM requests WHERE id = ?`,
        message.requestId,
      );
      if (current?.status !== "pending") {
        console.log(
          JSON.stringify({
            event: "approval_push_skipped",
            reason: "request_no_longer_pending",
          }),
        );
        return;
      }
    }
    let result: PushDeliveryResult;
    try {
      result = await deliverWebPush(
        {
          auth: row.auth,
          endpoint: row.endpoint,
          expirationTime: row.expiration_time,
          p256dh: row.p256dh,
        },
        message,
        {
          privateKey: this.env.VAPID_PRIVATE_KEY!,
          publicKey: this.env.VAPID_PUBLIC_KEY!,
          subject: this.env.VAPID_SUBJECT!,
        },
      );
    } catch {
      result = { failureStage: "unknown", outcome: "retry" };
    }
    console.log(
      JSON.stringify({
        event: "approval_push_delivery_completed",
        failureName: result.failureName ?? "none",
        failureStage: result.failureStage ?? "none",
        outcome: result.outcome,
        providerStatus: result.status ?? "no_response",
      }),
    );
    if (result.outcome === "delivered") {
      this.sql.exec(
        `UPDATE push_subscriptions
         SET last_success_at = ?, failure_count = 0 WHERE device_id = ?`,
        Date.now(),
        row.device_id,
      );
      return;
    }
    if (result.outcome === "gone") {
      this.sql.exec(
        `DELETE FROM push_subscriptions WHERE device_id = ?`,
        row.device_id,
      );
      this.broadcastHumanEvent("management.changed", row.device_id);
      return;
    }
    const failure = this.first<{ failure_count: number }>(
      `UPDATE push_subscriptions SET failure_count = failure_count + 1
       WHERE device_id = ? RETURNING failure_count`,
      row.device_id,
    );
    if ((failure?.failure_count ?? 0) >= PUSH_FAILURE_DELETE_THRESHOLD) {
      this.sql.exec(
        `DELETE FROM push_subscriptions WHERE device_id = ?`,
        row.device_id,
      );
      this.broadcastHumanEvent("management.changed", row.device_id);
    }
  }
}
