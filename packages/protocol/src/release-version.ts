const PRODUCT_VERSION_PATTERN =
  /^((?:0|[1-9]\d*))\.((?:0|[1-9]\d*))\.((?:0|[1-9]\d*))(?:-(alpha|beta)\.([1-9]\d*))?$/u;

export type OneNodReleaseChannel = "alpha" | "beta" | "stable";

export interface OneNodProductVersion {
  channel: OneNodReleaseChannel;
  version: string;
}

export function parseOneNodProductVersion(
  value: unknown,
): OneNodProductVersion | null {
  if (typeof value !== "string") return null;
  const match = PRODUCT_VERSION_PATTERN.exec(value);
  if (!match) return null;
  for (const numericPart of [match[1], match[2], match[3], match[5]]) {
    if (
      numericPart !== undefined &&
      !Number.isSafeInteger(Number(numericPart))
    ) {
      return null;
    }
  }
  return {
    channel: (match[4] ?? "stable") as OneNodReleaseChannel,
    version: value,
  };
}
