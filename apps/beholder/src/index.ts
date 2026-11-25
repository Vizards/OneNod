import { BeholderDecision } from "./session";

export { BeholderDecision };

declare const ONENOD_RELEASE_CHANNEL: string;
declare const ONENOD_RELEASE_VERSION: string;
declare const ONENOD_SOURCE_COMMIT: string;

// This Worker has no public route. The Gateway authenticates both the
// requester and the human before forwarding requests through its binding.
export default {
  async fetch(request: Request, env: BeholderEnv): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/internal/version" && request.method === "GET") {
      return Response.json({
        service: "onenod-beholder",
        release_channel: typeof ONENOD_RELEASE_CHANNEL === "string" ? ONENOD_RELEASE_CHANNEL : "development",
        release_version: typeof ONENOD_RELEASE_VERSION === "string" ? ONENOD_RELEASE_VERSION : "development",
        source_commit: typeof ONENOD_SOURCE_COMMIT === "string" ? ONENOD_SOURCE_COMMIT : "unknown",
      }, { headers: { "cache-control": "no-store" } });
    }
    const match = path.match(/^\/internal\/decisions\/([a-zA-Z0-9._:-]{8,96})\/(primary|comparison)\/(start|step|trace)$/u);
    if (!match) return new Response(null, { status: 404 });
    const [, evidenceId, variant, action] = match;
    if ((action === "trace" && request.method !== "GET") ||
        (action !== "trace" && request.method !== "POST")) {
      return new Response(null, { status: 404 });
    }
    const object = env.DECISIONS.getByName(`${evidenceId}:${variant}`);
    return object.fetch(request);
  },
} satisfies ExportedHandler<BeholderEnv>;
