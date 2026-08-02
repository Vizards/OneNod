import { decodeBase64Url } from "@onenod/protocol";

export type BootstrapFragment =
  | { status: "invalid" }
  | { status: "missing" }
  | { status: "ready"; token: string };

interface BootstrapLocation {
  hash: string;
  pathname: string;
  search: string;
}

interface BootstrapHistory {
  readonly state: unknown;
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}

/**
 * Moves the one-time bootstrap secret from the URL fragment into page memory.
 * The fragment is stripped before the caller can make any network request.
 */
export function consumeBootstrapFragment(
  location: BootstrapLocation,
  history: BootstrapHistory,
): BootstrapFragment {
  const rawFragment = location.hash.startsWith("#")
    ? location.hash.slice(1)
    : location.hash;

  if (!rawFragment) return { status: "missing" };

  // Request deep links and other ordinary application fragments are not
  // bootstrap material. Leave them intact for the router. Bootstrap-looking
  // fragments are stripped even when malformed so a mistyped one-time secret
  // does not linger in browser history.
  const bootstrapCandidate = /(?:^|&)bootstrap(?:=|&|$)/iu.test(rawFragment);
  if (!bootstrapCandidate) return { status: "missing" };

  if (rawFragment) {
    history.replaceState(
      history.state,
      "",
      `${location.pathname}${location.search}`,
    );
  }

  const exact = /^bootstrap=([A-Za-z0-9_-]+)$/u.exec(rawFragment);
  if (!exact) return { status: "invalid" };

  try {
    const token = decodeUtf8Base64Url(exact[1]!);
    return token ? { status: "ready", token } : { status: "invalid" };
  } catch {
    return { status: "invalid" };
  }
}

function decodeUtf8Base64Url(value: string): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(value));
}
