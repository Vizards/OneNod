declare const ONENOD_RELEASE_TAG: string | undefined;
declare const ONENOD_RELEASE_VERSION: string | undefined;
declare const ONENOD_RELEASE_CHANNEL: string | undefined;
declare const ONENOD_SOURCE_COMMIT: string | undefined;

import {
  parseOneNodProductVersion,
  type OneNodReleaseChannel,
} from "@onenod/protocol";

const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;

export type ExecutorReleaseChannel = OneNodReleaseChannel | "dev";

interface ExecutorReleaseInput {
  channel?: string | undefined;
  commit?: string | undefined;
  tag?: string | undefined;
  version?: string | undefined;
}

function injected(
  name: "channel" | "commit" | "tag" | "version",
): string | undefined {
  if (name === "channel") {
    return typeof ONENOD_RELEASE_CHANNEL === "string"
      ? ONENOD_RELEASE_CHANNEL
      : undefined;
  }
  if (name === "tag") {
    return typeof ONENOD_RELEASE_TAG === "string" ? ONENOD_RELEASE_TAG : undefined;
  }
  if (name === "version") {
    return typeof ONENOD_RELEASE_VERSION === "string"
      ? ONENOD_RELEASE_VERSION
      : undefined;
  }
  return typeof ONENOD_SOURCE_COMMIT === "string"
    ? ONENOD_SOURCE_COMMIT
    : undefined;
}

export function resolveExecutorRelease(input: ExecutorReleaseInput): Readonly<{
  channel: ExecutorReleaseChannel;
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
      sourceCommit: "unknown",
      tag: "dev",
      version: "0.0.0-dev",
    });
  }

  if (
    input.version === undefined ||
    input.tag === undefined ||
    input.commit === undefined
  ) {
    throw new Error("incomplete_executor_release_metadata");
  }

  const parsedVersion = parseOneNodProductVersion(input.version);
  if (!parsedVersion) throw new Error("invalid_executor_release_version");
  const derivedChannel = parsedVersion.channel;
  if (input.tag !== `v${input.version}`) {
    throw new Error("executor_release_tag_mismatch");
  }
  if (!COMMIT_PATTERN.test(input.commit)) {
    throw new Error("invalid_executor_source_commit");
  }
  if (input.channel !== undefined && input.channel !== derivedChannel) {
    throw new Error("executor_release_channel_mismatch");
  }

  return Object.freeze({
    channel: derivedChannel,
    sourceCommit: input.commit,
    tag: input.tag,
    version: input.version,
  });
}

export const EXECUTOR_RELEASE = resolveExecutorRelease({
  channel: injected("channel"),
  commit: injected("commit"),
  tag: injected("tag"),
  version: injected("version"),
});
