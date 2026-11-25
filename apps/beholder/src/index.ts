import { BeholderDecision } from "./session";

export { BeholderDecision };

// This Worker has no public route. The Gateway authenticates both the
// requester and the human before forwarding requests through its binding.
export default {
  async fetch(request: Request, env: BeholderEnv): Promise<Response> {
    const path = new URL(request.url).pathname;
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
