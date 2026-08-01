declare const ONENOD_RELEASE_TAG: string | undefined;
declare const ONENOD_RELEASE_VERSION: string | undefined;
declare const ONENOD_SOURCE_COMMIT: string | undefined;

export const REQUESTER_PROTOCOL_MIN = 1;
export const REQUESTER_PROTOCOL_MAX = 1;
export const GATEWAY_EXECUTOR_PROTOCOL_MIN = 1;
export const GATEWAY_EXECUTOR_PROTOCOL_MAX = 1;
export const GATEWAY_STATE_SCHEMA = 1;
export const EXECUTOR_STATE_SCHEMA = 1;

export const GATEWAY_RELEASE_METADATA = Object.freeze({
  gatewayStateSchema: GATEWAY_STATE_SCHEMA,
  executorProtocolMax: GATEWAY_EXECUTOR_PROTOCOL_MAX,
  executorProtocolMin: GATEWAY_EXECUTOR_PROTOCOL_MIN,
  executorStateSchema: EXECUTOR_STATE_SCHEMA,
  pwaReleaseVersion: buildValue(
    typeof ONENOD_RELEASE_VERSION === "undefined" ? undefined : ONENOD_RELEASE_VERSION,
    "0.0.0-dev",
  ),
  releaseTag: buildValue(
    typeof ONENOD_RELEASE_TAG === "undefined" ? undefined : ONENOD_RELEASE_TAG,
    "dev",
  ),
  releaseVersion: buildValue(
    typeof ONENOD_RELEASE_VERSION === "undefined" ? undefined : ONENOD_RELEASE_VERSION,
    "0.0.0-dev",
  ),
  requesterProtocolMax: REQUESTER_PROTOCOL_MAX,
  requesterProtocolMin: REQUESTER_PROTOCOL_MIN,
  sourceCommit: buildValue(
    typeof ONENOD_SOURCE_COMMIT === "undefined" ? undefined : ONENOD_SOURCE_COMMIT,
    "development",
  ),
});

function buildValue(value: string | undefined, fallback: string): string {
  if (!value || value.length > 128 || hasControlCharacter(value)) {
    return fallback;
  }
  return value;
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}
