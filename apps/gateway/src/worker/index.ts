import {
  API_PATHS,
  type SystemHealthResponse,
} from "@onenod/protocol";

import { GATEWAY_RELEASE_METADATA } from "./release-metadata.js";
import type { GatewayReleaseChannel } from "../release.js";

const VERSION_PATH = "/api/version";

export { ApprovalCoordinator } from "./approval-coordinator.js";

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === VERSION_PATH) {
      return json(releaseMetadataResponse(await beholderReleaseMetadata(env)));
    }

    if (url.pathname.startsWith("/v1/")) {
      return env.APPROVALS.getByName("global").fetch(request);
    }

    if (request.method === "GET" && url.pathname === API_PATHS.systemHealth) {
      const body: SystemHealthResponse & { channel: GatewayReleaseChannel } = {
        channel: GATEWAY_RELEASE_METADATA.releaseChannel,
        environment: env.APP_ENV,
        ok: true,
        service: "onenod-gateway",
        version: GATEWAY_RELEASE_METADATA.releaseVersion,
      };
      return json(body);
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "not_found", ok: false }, 404);
    }

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;

async function beholderReleaseMetadata(env: Env): Promise<{
  available: boolean; channel?: string; version?: string; source_commit?: string;
} | undefined> {
  if (!env.BEHOLDER_SERVICE) return undefined;
  try {
    const response = await env.BEHOLDER_SERVICE.fetch("https://beholder.internal/internal/version", {
      signal: AbortSignal.timeout(3_000),
    });
    if (!response.ok) return { available: false };
    const body: unknown = await response.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return { available: false };
    const value = body as Record<string, unknown>;
    if (value.service !== "onenod-beholder" || typeof value.release_channel !== "string" ||
        typeof value.release_version !== "string" || typeof value.source_commit !== "string" ||
        value.release_channel.length > 32 || value.release_version.length > 64 || value.source_commit.length > 64) {
      return { available: false };
    }
    return { available: true, channel: value.release_channel, version: value.release_version, source_commit: value.source_commit };
  } catch {
    return { available: false };
  }
}

function releaseMetadataResponse(beholder?: {
  available: boolean; channel?: string; version?: string; source_commit?: string;
}) {
  const releaseVersion = GATEWAY_RELEASE_METADATA.releaseVersion;
  return {
    components: {
      ...(beholder ? { beholder } : {}),
      executor: {
        accepted_gateway_protocol: {
          max: GATEWAY_RELEASE_METADATA.executorProtocolMax,
          min: GATEWAY_RELEASE_METADATA.executorProtocolMin,
        },
        declared: true,
        channel: GATEWAY_RELEASE_METADATA.releaseChannel,
        state_schema: GATEWAY_RELEASE_METADATA.executorStateSchema,
        version: releaseVersion,
      },
      gateway: {
        accepted_client_protocol: {
          max: GATEWAY_RELEASE_METADATA.requesterProtocolMax,
          min: GATEWAY_RELEASE_METADATA.requesterProtocolMin,
        },
        channel: GATEWAY_RELEASE_METADATA.releaseChannel,
        state_schema: GATEWAY_RELEASE_METADATA.gatewayStateSchema,
        version: releaseVersion,
      },
      pwa: {
        channel: GATEWAY_RELEASE_METADATA.pwaReleaseChannel,
        version: GATEWAY_RELEASE_METADATA.pwaReleaseVersion,
      },
    },
    ok: true,
    release_tag: GATEWAY_RELEASE_METADATA.releaseTag,
    release_channel: GATEWAY_RELEASE_METADATA.releaseChannel,
    release_version: releaseVersion,
    service: "onenod-gateway",
    source_commit: GATEWAY_RELEASE_METADATA.sourceCommit,
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
    status,
  });
}
