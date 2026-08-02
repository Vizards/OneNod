import { resolveGatewayRelease } from "../release";

const RELEASE = resolveGatewayRelease({
  channel: import.meta.env.VITE_ONENOD_RELEASE_CHANNEL,
  commit: import.meta.env.VITE_ONENOD_SOURCE_COMMIT,
  tag: import.meta.env.VITE_ONENOD_RELEASE_TAG,
  version: import.meta.env.VITE_ONENOD_RELEASE_VERSION,
});

export const PWA_RELEASE_METADATA = Object.freeze({
  releaseChannel: RELEASE.channel,
  releaseTag: RELEASE.tag,
  releaseVersion: RELEASE.version,
  sourceCommit: RELEASE.sourceCommit,
});
