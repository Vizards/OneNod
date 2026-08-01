declare const ONENOD_RELEASE_TAG: string | undefined;
declare const ONENOD_RELEASE_VERSION: string | undefined;
declare const ONENOD_SOURCE_COMMIT: string | undefined;

const VERSION_PATTERN = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;

function injected(name: "tag" | "version" | "commit"): string | undefined {
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

const candidateVersion = injected("version");
const candidateCommit = injected("commit");
const candidateTag = injected("tag");

export const EXECUTOR_RELEASE = Object.freeze({
  sourceCommit:
    candidateCommit && COMMIT_PATTERN.test(candidateCommit)
      ? candidateCommit
      : "unknown",
  tag:
    candidateTag && candidateVersion && candidateTag === `v${candidateVersion}`
      ? candidateTag
      : "dev",
  version:
    candidateVersion && VERSION_PATTERN.test(candidateVersion)
      ? candidateVersion
      : "0.0.0-dev",
});
