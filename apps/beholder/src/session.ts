import { DurableObject } from "cloudflare:workers";

import policy from "../../../cmd/beholder-gatekeeper/retrieval-policy.txt";
import tools from "../../../cmd/beholder-gatekeeper/internal/retrieval/tools.json";

const MAX_ROUNDS = 24;
const MAX_CALLS = 32;
const MAX_MODEL_REQUEST = 16 * 1024 * 1024;
const MAX_MODEL_RESPONSE = 8 * 1024 * 1024;
const MAX_TRACE = 32 * 1024 * 1024;
const CHUNK_SIZE = 256 * 1024;
const TRACE_RETENTION_MS = 7 * 24 * 60 * 60_000;
const allowedTools = new Set(tools.map((tool) => tool.function.name));
const encoder = new TextEncoder();

type Variant = "primary" | "comparison";
type Phase = "processing" | "waiting" | "finished";
type RecordValue = Record<string, unknown>;

interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

interface DecisionState {
  schema: 1;
  evidenceId: string;
  requesterDeviceId: string;
  variant: Variant;
  requestedModel: string;
  endpointHash: string;
  capabilityHash: string;
  phase: Phase;
  createdAt: number;
  deadline: number;
  round: number;
  eventCount: number;
  traceBytes: number;
  modelCalled: boolean;
  readEvidence: boolean;
  pending: ToolCall[];
  seenCallIds: string[];
}

interface TraceEvent {
  kind: "initial" | "assistant" | "tool" | "result";
  value: unknown;
}

interface DecisionResult {
  decision: "allow" | "escalate";
  reason: string;
  error_code?: string;
  model_called: boolean;
  model_used: boolean;
  model_rounds: number;
  evidence_refs?: unknown;
  scope_resolution?: unknown;
}

export class BeholderDecision extends DurableObject<BeholderEnv> {
  private processing = false;

  override async fetch(request: Request): Promise<Response> {
    const match = new URL(request.url).pathname.match(
      /^\/internal\/decisions\/([a-zA-Z0-9._:-]{8,96})\/(primary|comparison)\/(start|step|trace)$/u,
    );
    if (!match) return failure("not_found", 404);
    const evidenceId = match[1]!;
    const variant = match[2]! as Variant;
    const action = match[3]!;
    try {
      if (action === "trace" && request.method === "GET") {
        return await this.trace(evidenceId, variant);
      }
      if (request.method !== "POST") return failure("not_found", 404);
      if (this.processing) return failure("decision_busy", 409);
      this.processing = true;
      try {
        const body = record(await request.json());
        if (!body) return failure("decision_input_invalid", 400);
        return action === "start"
          ? await this.start(evidenceId, variant, body)
          : action === "step"
            ? await this.step(evidenceId, variant, body)
            : failure("not_found", 404);
      } finally {
        this.processing = false;
      }
    } catch {
      // Input, provider bodies and trace contents can contain private data.
      return failure("decision_unavailable", 503);
    }
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }

  private async start(evidenceId: string, variant: Variant, body: RecordValue): Promise<Response> {
    if (await this.ctx.storage.get("state")) return failure("decision_exists", 409);
    const requester = body.requester_device_id;
    const input = body.input;
    const budget = body.budget_ms;
    const maximumBudget = variant === "primary" ? 30_000 : 180_000;
    if (typeof requester !== "string" || !/^[a-zA-Z0-9._:-]{8,128}$/u.test(requester) ||
        typeof input !== "string" || encoder.encode(input).byteLength > 256 * 1024 ||
        typeof budget !== "number" || !Number.isInteger(budget) || budget <= 0 || budget > maximumBudget) {
      return failure("decision_input_invalid", 400);
    }
    // Validate the trace key before making a model call.
    await this.traceKey();
    const capability = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const now = Date.now();
    const state: DecisionState = {
      schema: 1, evidenceId, requesterDeviceId: requester, variant,
      requestedModel: this.env.BEHOLDER_MODEL,
      endpointHash: await digest(this.env.BEHOLDER_PROVIDER_URL),
      capabilityHash: await digest(capability), phase: "processing",
      createdAt: now, deadline: now + budget, round: 0, eventCount: 0,
      traceBytes: 0, modelCalled: false, readEvidence: false, pending: [], seenCallIds: [],
    };
    await this.ctx.storage.put("state", state);
    await this.ctx.storage.setAlarm(now + TRACE_RETENTION_MS);
    await this.append(state, { kind: "initial", value: { input, policy } });
    const result = await this.callModel(state);
    return json({ ...result, capability });
  }

  private async step(evidenceId: string, variant: Variant, body: RecordValue): Promise<Response> {
    const state = await this.ctx.storage.get<DecisionState>("state");
    if (!state || state.evidenceId !== evidenceId || state.variant !== variant ||
        state.requesterDeviceId !== body.requester_device_id || typeof body.capability !== "string" ||
        !(await sameDigest(body.capability, state.capabilityHash))) {
      return failure("decision_not_found", 404);
    }
    if (state.phase !== "waiting" || body.round !== state.round || !Array.isArray(body.outputs) ||
        body.outputs.length !== state.pending.length) {
      return failure("decision_step_invalid", 409);
    }
    const outputs: Array<{ tool_call_id: string; content: string }> = [];
    for (let index = 0; index < state.pending.length; index += 1) {
      const output = record(body.outputs[index]);
      if (!output || output.tool_call_id !== state.pending[index]!.id ||
          typeof output.content !== "string" || encoder.encode(output.content).byteLength > 2 * 1024 * 1024) {
        return failure("decision_step_invalid", 400);
      }
      let parsed: RecordValue | undefined;
      try { parsed = record(JSON.parse(output.content)); } catch { /* Invalid tool results do not count as reads. */ }
      if (parsed && (parsed.error === undefined || parsed.error === "")) state.readEvidence = true;
      outputs.push({ tool_call_id: state.pending[index]!.id, content: output.content });
    }
    state.phase = "processing";
    await this.ctx.storage.put("state", state);
    for (const output of outputs) await this.append(state, { kind: "tool", value: output });
    state.pending = [];
    return json(await this.callModel(state));
  }

  private async callModel(state: DecisionState): Promise<RecordValue> {
    const finish = async (code: string, reason: string): Promise<RecordValue> => {
      const result: DecisionResult = {
        decision: "escalate", reason, error_code: code,
        model_called: state.modelCalled, model_used: false, model_rounds: state.round,
      };
      await this.complete(state, result);
      return { phase: "finished", result };
    };
    if (Date.now() >= state.deadline) return finish("model-timeout", "The model decision exceeded its time budget.");
    if (state.round >= MAX_ROUNDS) return finish("model-round-budget-exhausted", "The model exceeded its review round limit.");
    const endpoint = validEndpoint(this.env.BEHOLDER_PROVIDER_URL);
    if (!endpoint || !this.env.BEHOLDER_PROVIDER_KEY ||
        ["\r", "\n", "\0"].some((character) => this.env.BEHOLDER_PROVIDER_KEY.includes(character)) ||
        !this.env.BEHOLDER_MODEL || this.env.BEHOLDER_MODEL.length > 256) {
      return finish("model-not-configured", "The model service is not configured.");
    }
    if (state.requestedModel !== this.env.BEHOLDER_MODEL ||
        state.endpointHash !== await digest(this.env.BEHOLDER_PROVIDER_URL)) {
      return finish("model-configuration-changed", "The model configuration changed during this review.");
    }
    const events = await this.events(state);
    const initial = record(events.find((event) => event.kind === "initial")?.value);
    if (!initial || typeof initial.input !== "string") return finish("decision-context-unavailable", "The review context is unavailable.");
    const messages: RecordValue[] = [
      { role: "system", content: policy },
      { role: "user", content: initial.input },
    ];
    for (const event of events) {
      if (event.kind === "assistant") {
        const value = record(event.value);
        const message = record(value?.message);
        if (message) messages.push(message);
      } else if (event.kind === "tool") {
        const value = record(event.value);
        if (value) messages.push({ role: "tool", tool_call_id: value.tool_call_id, content: value.content });
      }
    }
    const requestBody = JSON.stringify({
      model: this.env.BEHOLDER_MODEL, messages, stream: false,
      thinking: { type: state.variant === "primary" ? "disabled" : "enabled" },
      response_format: { type: "json_object" }, tools, tool_choice: "auto",
    });
    if (encoder.encode(requestBody).byteLength > MAX_MODEL_REQUEST) {
      return finish("model-request-too-large", "The review exceeded the model request size limit.");
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1, state.deadline - Date.now()));
    let response: Response;
    state.modelCalled = true;
    state.round += 1;
    await this.ctx.storage.put("state", state);
    try {
      response = await fetch(endpoint, {
        method: "POST", redirect: "manual", signal: controller.signal,
        headers: { "content-type": "application/json", authorization: `Bearer ${this.env.BEHOLDER_PROVIDER_KEY}` },
        body: requestBody,
      });
    } catch {
      clearTimeout(timer);
      return finish(Date.now() >= state.deadline ? "model-timeout" : "model-transport-error", "The model service could not complete the review.");
    }
    if (!response.ok) {
      clearTimeout(timer);
      await response.body?.cancel();
      return finish(`model-http-${response.status}`, "The model service rejected the review request.");
    }
    let decoded: unknown;
    try { decoded = JSON.parse(await readLimited(response, MAX_MODEL_RESPONSE)); } catch {
      clearTimeout(timer);
      return Date.now() >= state.deadline
        ? finish("model-timeout", "The model decision exceeded its time budget.")
        : finish("model-response-unreadable", "The model response was unavailable or too large.");
    }
    clearTimeout(timer);
    const completion = record(decoded);
    const choices = completion?.choices;
    const choice = Array.isArray(choices) && choices.length === 1 ? record(choices[0]) : undefined;
    const message = record(choice?.message);
    if (!message || message.role !== "assistant") return finish("model-message-invalid", "The model returned an invalid response.");
    await this.append(state, { kind: "assistant", value: {
      message, finish_reason: choice?.finish_reason, usage: completion?.usage,
      ...(typeof completion?.model === "string" ? { response_model: completion.model } : {}),
    } });
    const calls = parseCalls(message.tool_calls, state.seenCallIds);
    if (calls === undefined) return finish("model-tool-call-invalid", "The model returned an invalid context request.");
    if (calls.length) {
      if (choice?.finish_reason !== "tool_calls") return finish("model-tool-call-invalid", "The model returned an incomplete context request.");
      state.pending = calls;
      state.seenCallIds.push(...calls.map((call) => call.id));
      state.phase = "waiting";
      await this.ctx.storage.put("state", state);
      return { phase: "tools", round: state.round, calls };
    }
    let decision: RecordValue | undefined;
    try { decision = typeof message.content === "string" ? record(JSON.parse(message.content)) : undefined; } catch { /* Invalid model decisions fail closed. */ }
    if (choice?.finish_reason !== "stop" || !decision ||
        (decision.decision !== "allow" && decision.decision !== "escalate") ||
        typeof decision.reason !== "string" || decision.reason.length === 0 ||
        decision.reason.trim() !== decision.reason || decision.reason.includes("\0")) {
      return finish("model-decision-invalid", "The model did not return a valid decision.");
    }
    if (!state.readEvidence) return finish("model-retrieval-unused", "The model did not successfully read context.");
    const result: DecisionResult = {
      decision: decision.decision, reason: decision.reason, model_called: true, model_used: true,
      model_rounds: state.round,
      ...(decision.evidence_refs === undefined ? {} : { evidence_refs: decision.evidence_refs }),
      ...(decision.scope_resolution === undefined ? {} : { scope_resolution: decision.scope_resolution }),
    };
    await this.complete(state, result);
    return { phase: "finished", result };
  }

  private async complete(state: DecisionState, result: DecisionResult): Promise<void> {
    await this.append(state, { kind: "result", value: result });
    state.phase = "finished";
    state.pending = [];
    await this.ctx.storage.put("state", state);
  }

  private async trace(evidenceId: string, variant: Variant): Promise<Response> {
    const state = await this.ctx.storage.get<DecisionState>("state");
    if (!state || state.evidenceId !== evidenceId || state.variant !== variant) return failure("decision_not_found", 404);
    const events = await this.events(state);
    const interrupted = state.phase !== "finished" && Date.now() >= state.deadline;
    if (interrupted) {
      events.push({
        kind: "result",
        value: {
          decision: "escalate", reason: "The review did not finish within its time budget.",
          error_code: "worker-decision-interrupted", model_called: state.modelCalled,
          model_used: false, model_rounds: state.round,
        },
      });
    }
    return json({
      evidence_id: evidenceId, variant, phase: interrupted ? "finished" : state.phase,
      requested_model: state.requestedModel,
      created_at: new Date(state.createdAt).toISOString(),
      expires_at: new Date(state.createdAt + TRACE_RETENTION_MS).toISOString(),
      events,
    });
  }

  private async append(state: DecisionState, event: TraceEvent): Promise<void> {
    const data = encoder.encode(JSON.stringify(event));
    if (state.traceBytes + data.byteLength > MAX_TRACE) throw new Error("trace_capacity_exceeded");
    const key = await this.traceKey();
    const index = state.eventCount;
    const chunks = Math.max(1, Math.ceil(data.byteLength / CHUNK_SIZE));
    for (let chunk = 0; chunk < chunks; chunk += 1) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = data.slice(chunk * CHUNK_SIZE, (chunk + 1) * CHUNK_SIZE);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: eventAad(state, index, chunk) }, key, plaintext,
      );
      await this.ctx.storage.put(`event:${index}:${chunk}`, { iv, encrypted });
    }
    await this.ctx.storage.put(`event:${index}:chunks`, chunks);
    state.eventCount += 1;
    state.traceBytes += data.byteLength;
    await this.ctx.storage.put("state", state);
  }

  private async events(state: DecisionState): Promise<TraceEvent[]> {
    const result: TraceEvent[] = [];
    const key = await this.traceKey();
    for (let index = 0; index < state.eventCount; index += 1) {
      const count = await this.ctx.storage.get<number>(`event:${index}:chunks`);
      if (!count || count > Math.ceil(MAX_TRACE / CHUNK_SIZE)) throw new Error("trace_invalid");
      const parts: Uint8Array[] = [];
      let length = 0;
      for (let chunk = 0; chunk < count; chunk += 1) {
        const part = await this.ctx.storage.get<{ iv: Uint8Array; encrypted: ArrayBuffer }>(`event:${index}:${chunk}`);
        if (!part) throw new Error("trace_invalid");
        const decoded = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: ownedBytes(part.iv), additionalData: eventAad(state, index, chunk) }, key, part.encrypted,
        ));
        parts.push(decoded);
        length += decoded.byteLength;
      }
      const data = new Uint8Array(length);
      let offset = 0;
      for (const part of parts) { data.set(part, offset); offset += part.byteLength; }
      result.push(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data)) as TraceEvent);
    }
    return result;
  }

  private async traceKey(): Promise<CryptoKey> {
    const raw = fromBase64url(this.env.BEHOLDER_TRACE_KEY);
    if (raw.byteLength !== 32) throw new Error("trace_key_invalid");
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
}

function parseCalls(value: unknown, seen: string[]): ToolCall[] | undefined {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_CALLS) return undefined;
  const ids = new Set(seen);
  const result: ToolCall[] = [];
  for (const entry of value) {
    const call = record(entry);
    const fn = record(call?.function);
    if (!call || call.type !== "function" || typeof call.id !== "string" || call.id.length === 0 ||
        call.id.length > 1024 || ids.has(call.id) || !fn || typeof fn.name !== "string" ||
        !allowedTools.has(fn.name) || typeof fn.arguments !== "string" || fn.arguments.length > 16 * 1024) return undefined;
    ids.add(call.id);
    result.push({ id: call.id, type: "function", function: { name: fn.name, arguments: fn.arguments } });
  }
  return result;
}

function validEndpoint(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return undefined;
    return url.toString();
  } catch { return undefined; }
}

function record(value: unknown): RecordValue | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : undefined;
}

function eventAad(state: DecisionState, index: number, chunk: number): Uint8Array<ArrayBuffer> {
  return encoder.encode(`onenod-beholder-trace-v1\n${state.evidenceId}\n${state.variant}\n${index}\n${chunk}`);
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function fromBase64url(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("invalid_base64url");
  const text = atob(value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4));
  const result = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) result[index] = text.charCodeAt(index);
  return result;
}

function ownedBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(value.byteLength);
  result.set(value);
  return result;
}

async function digest(value: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

async function sameDigest(value: string, expected: string): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  const actual = await digest(value);
  let difference = actual.length ^ expected.length;
  for (let index = 0; index < actual.length; index += 1) difference |= actual.charCodeAt(index) ^ (expected.charCodeAt(index) || 0);
  return difference === 0;
}

async function readLimited(response: Response, maximum: number): Promise<string> {
  if (!response.body) throw new Error("empty_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximum) { await reader.cancel(); throw new Error("response_too_large"); }
    chunks.push(value);
  }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder("utf-8", { fatal: true }).decode(data);
}

function json(value: unknown): Response {
  return Response.json(value, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

function failure(code: string, status: number): Response {
  return Response.json({ error: code }, { status, headers: { "cache-control": "no-store" } });
}
