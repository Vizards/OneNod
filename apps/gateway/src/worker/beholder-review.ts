import { ApprovalRequestStore } from "./approval-request-store.js";
import {
  assertExactKeys,
  GatewayHttpError,
  safeBeholderDiagnostic,
} from "./approval-http.js";
import { HumanAccess } from "./human-access.js";
import { RequesterAccess } from "./requester-access.js";

const MAX_DECISION_MESSAGE_BYTES = 16 * 1024 * 1024;
const MAX_BUFFERED_DECISION_BYTES = 24 * 1024 * 1024;
const MAX_CONCURRENT_DECISION_MESSAGES = 12;

export class BeholderReview {
  private readonly starts = new Map<string, { count: number; until: number }>();
  private bufferedBytes = 0;
  private submissions = 0;

  constructor(
    private readonly env: Env,
    private readonly human: HumanAccess,
    private readonly requester: RequesterAccess,
    private readonly requests: ApprovalRequestStore,
  ) {}

  async submit(
    request: Request,
    path: string,
    evidenceId: string,
    variant: string,
    action: string,
  ): Promise<Response> {
    // Authenticate a bounded, signed digest envelope before accepting the
    // potentially much larger context. The actual bytes are checked below.
    const digest = request.headers.get("x-onenod-beholder-content-sha256");
    const sizeText = request.headers.get("x-onenod-beholder-content-bytes");
    if (!digest || !/^[0-9a-f]{64}$/u.test(digest) || !sizeText ||
        !/^[1-9][0-9]{0,7}$/u.test(sizeText)) {
      throw new GatewayHttpError("beholder_input_invalid", 400);
    }
    const size = Number(sizeText);
    if (size > MAX_DECISION_MESSAGE_BYTES) throw new GatewayHttpError("request_too_large", 413);
    const requester = await this.requester.authenticateSignedRequest(request, path, {
      content_bytes: size, content_sha256: digest,
    });
    this.human.assertGatewayUnlocked();
    if (!this.env.BEHOLDER_SERVICE) throw new GatewayHttpError("beholder_unavailable", 503);
    if (action === "start") this.limitStarts(requester.deviceId);
    if (this.submissions >= MAX_CONCURRENT_DECISION_MESSAGES ||
        this.bufferedBytes + size > MAX_BUFFERED_DECISION_BYTES) {
      throw new GatewayHttpError("beholder_capacity_exceeded", 503);
    }
    this.submissions += 1;
    this.bufferedBytes += size;
    try {
      const body = await readSignedBody(request, size, digest);
      assertExactKeys(body, action === "start"
        ? ["input", "budget_ms"]
        : ["capability", "round", "outputs"]);
      this.human.assertGatewayUnlocked();
      this.requester.assertRequesterActive(requester.deviceId);
      const response = await this.env.BEHOLDER_SERVICE.fetch(
        `https://beholder.internal/internal/decisions/${evidenceId}/${variant}/${action}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ...body, requester_device_id: requester.deviceId }),
        },
      );
      this.human.assertGatewayUnlocked();
      this.requester.assertRequesterActive(requester.deviceId);
      return response;
    } finally {
      this.submissions -= 1;
      this.bufferedBytes -= size;
    }
  }

  private limitStarts(deviceId: string): void {
    const now = Date.now();
    for (const [id, window] of this.starts) {
      if (window.until <= now) this.starts.delete(id);
    }
    const window = this.starts.get(deviceId) ?? { count: 0, until: now + 60_000 };
    if (window.count >= 60) throw new GatewayHttpError("beholder_rate_limited", 429);
    window.count += 1;
    this.starts.set(deviceId, window);
  }

  async trace(request: Request, requestId: string, variant: string): Promise<Response> {
    await this.human.requireHumanSession(request);
    const row = this.requests.findRequestRow(requestId) ?? this.requests.requestActivityRow(requestId);
    if (!row) throw new GatewayHttpError("request_not_found", 404);
    let diagnosticEvidence: string | undefined;
    try {
      if (row.beholder_diagnostic) {
        diagnosticEvidence = safeBeholderDiagnostic(JSON.parse(row.beholder_diagnostic)).evidence_id;
      }
    } catch {
      // Invalid requester diagnostics are never used for correlation.
    }
    const evidenceId = row.beholder_evidence_id ?? diagnosticEvidence;
    if (!evidenceId || !/^[a-zA-Z0-9._:-]{8,96}$/u.test(evidenceId) || !this.env.BEHOLDER_SERVICE) {
      throw new GatewayHttpError("beholder_trace_unavailable", 404);
    }
    const response = await this.env.BEHOLDER_SERVICE.fetch(
      `https://beholder.internal/internal/decisions/${evidenceId}/${variant}/trace`,
    );
    await this.human.requireHumanSession(request);
    return response;
  }
}

async function readSignedBody(request: Request, size: number, expectedDigest: string): Promise<Record<string, unknown>> {
  const declared = request.headers.get("content-length");
  if (declared !== null && declared !== String(size)) throw new GatewayHttpError("beholder_input_invalid", 400);
  if (!request.body) throw new GatewayHttpError("invalid_json", 400);
  const reader = request.body.getReader();
  const bytes = new Uint8Array(size);
  let offset = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (offset + value.byteLength > size) {
      await reader.cancel();
      throw new GatewayHttpError("request_too_large", 413);
    }
    bytes.set(value, offset);
    offset += value.byteLength;
  }
  if (offset !== size) throw new GatewayHttpError("beholder_input_invalid", 400);
  const actual = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const digest = Array.from(actual, (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (digest !== expectedDigest) throw new GatewayHttpError("beholder_input_invalid", 400);
  let body: unknown;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch {
    throw new GatewayHttpError("invalid_json", 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new GatewayHttpError("invalid_json", 400);
  return body as Record<string, unknown>;
}
