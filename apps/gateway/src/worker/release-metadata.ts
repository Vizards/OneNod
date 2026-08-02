declare const ONENOD_RELEASE_TAG: string | undefined;
declare const ONENOD_RELEASE_VERSION: string | undefined;
declare const ONENOD_RELEASE_CHANNEL: string | undefined;
declare const ONENOD_SOURCE_COMMIT: string | undefined;

import { resolveGatewayRelease } from "../release.js";

export const REQUESTER_PROTOCOL_MIN = 1;
export const REQUESTER_PROTOCOL_MAX = 1;
export const GATEWAY_EXECUTOR_PROTOCOL_MIN = 1;
export const GATEWAY_EXECUTOR_PROTOCOL_MAX = 1;
export const GATEWAY_STATE_SCHEMA = 1;
export const EXECUTOR_STATE_SCHEMA = 1;

const RELEASE = resolveGatewayRelease({
  channel:
    typeof ONENOD_RELEASE_CHANNEL === "undefined"
      ? undefined
      : ONENOD_RELEASE_CHANNEL,
  commit:
    typeof ONENOD_SOURCE_COMMIT === "undefined" ? undefined : ONENOD_SOURCE_COMMIT,
  tag: typeof ONENOD_RELEASE_TAG === "undefined" ? undefined : ONENOD_RELEASE_TAG,
  version:
    typeof ONENOD_RELEASE_VERSION === "undefined"
      ? undefined
      : ONENOD_RELEASE_VERSION,
});

export const GATEWAY_RELEASE_METADATA = Object.freeze({
  releaseChannel: RELEASE.channel,
  gatewayStateSchema: GATEWAY_STATE_SCHEMA,
  executorProtocolMax: GATEWAY_EXECUTOR_PROTOCOL_MAX,
  executorProtocolMin: GATEWAY_EXECUTOR_PROTOCOL_MIN,
  executorStateSchema: EXECUTOR_STATE_SCHEMA,
  pwaReleaseChannel: RELEASE.channel,
  pwaReleaseVersion: RELEASE.version,
  releaseTag: RELEASE.tag,
  releaseVersion: RELEASE.version,
  requesterProtocolMax: REQUESTER_PROTOCOL_MAX,
  requesterProtocolMin: REQUESTER_PROTOCOL_MIN,
  sourceCommit: RELEASE.sourceCommit,
});
