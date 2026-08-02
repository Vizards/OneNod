import {
  parseOneNodProductVersion,
  type OneNodReleaseChannel,
} from "@onenod/protocol";

const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;

export type GatewayReleaseChannel = OneNodReleaseChannel | "dev";

interface GatewayReleaseInput {
  channel?: string | undefined;
  commit?: string | undefined;
  tag?: string | undefined;
  version?: string | undefined;
}

export function resolveGatewayRelease(input: GatewayReleaseInput): Readonly<{
  channel: GatewayReleaseChannel;
  sourceCommit: string;
  tag: string;
  version: string;
}> {
  const hasPublishedMetadata =
    (input.channel !== undefined && input.channel !== "dev") ||
    input.commit !== undefined ||
    input.tag !== undefined ||
    input.version !== undefined;
  if (!hasPublishedMetadata) {
    return Object.freeze({
      channel: "dev",
      sourceCommit: "development",
      tag: "dev",
      version: "0.0.0-dev",
    });
  }

  if (
    input.version === undefined ||
    input.tag === undefined ||
    input.commit === undefined
  ) {
    throw new Error("incomplete_gateway_release_metadata");
  }

  const parsedVersion = parseOneNodProductVersion(input.version);
  if (!parsedVersion) throw new Error("invalid_gateway_release_version");
  const derivedChannel = parsedVersion.channel;
  if (input.tag !== `v${input.version}`) {
    throw new Error("gateway_release_tag_mismatch");
  }
  if (!COMMIT_PATTERN.test(input.commit)) {
    throw new Error("invalid_gateway_source_commit");
  }
  if (input.channel !== undefined && input.channel !== derivedChannel) {
    throw new Error("gateway_release_channel_mismatch");
  }

  return Object.freeze({
    channel: derivedChannel,
    sourceCommit: input.commit,
    tag: input.tag,
    version: input.version,
  });
}
