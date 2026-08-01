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

export const PWA_RELEASE_METADATA = Object.freeze({
  releaseTag: buildValue(import.meta.env.VITE_ONENOD_RELEASE_TAG, "dev"),
  releaseVersion: buildValue(
    import.meta.env.VITE_ONENOD_RELEASE_VERSION,
    "0.0.0-dev",
  ),
  sourceCommit: buildValue(
    import.meta.env.VITE_ONENOD_SOURCE_COMMIT,
    "development",
  ),
});
