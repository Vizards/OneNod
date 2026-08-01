import canonicalize from "canonicalize";

export type JsonPrimitive = boolean | null | number | string;

export type JsonValue =
  | JsonPrimitive
  | ReadonlyArray<JsonValue>
  | { readonly [key: string]: JsonValue };

function assertValidUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);

    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const nextCodeUnit = value.charCodeAt(index + 1);
      if (
        !Number.isFinite(nextCodeUnit) ||
        nextCodeUnit < 0xdc00 ||
        nextCodeUnit > 0xdfff
      ) {
        throw new TypeError("Canonical JSON does not permit lone Unicode surrogates.");
      }

      index += 1;
      continue;
    }

    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError("Canonical JSON does not permit lone Unicode surrogates.");
    }
  }
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertCanonicalDomain(value: unknown, ancestors: Set<object>): void {
  if (value === null) {
    return;
  }

  if (typeof value === "string") {
    assertValidUnicode(value);
    return;
  }

  if (typeof value === "boolean") {
    return;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Canonical JSON only permits finite numbers.");
    }
    return;
  }

  if (typeof value !== "object") {
    throw new TypeError(`Canonical JSON does not support values of type ${typeof value}.`);
  }

  if (ancestors.has(value)) {
    throw new TypeError("Canonical JSON does not support cyclic values.");
  }

  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new TypeError("Canonical JSON does not support sparse arrays.");
        }
        assertCanonicalDomain(value[index], ancestors);
      }

      const enumerableKeys = Object.keys(value);
      if (
        enumerableKeys.some(
          (key) =>
            !/^(0|[1-9]\d*)$/.test(key) ||
            !Number.isSafeInteger(Number(key)) ||
            Number(key) >= value.length,
        )
      ) {
        throw new TypeError("Canonical JSON arrays cannot have named enumerable properties.");
      }

      return;
    }

    if (!isPlainObject(value)) {
      throw new TypeError("Canonical JSON only supports arrays and plain objects.");
    }

    if (Object.getOwnPropertySymbols(value).some((symbol) =>
      Object.getOwnPropertyDescriptor(value, symbol)?.enumerable === true
    )) {
      throw new TypeError("Canonical JSON objects cannot have enumerable symbol properties.");
    }

    for (const key of Object.keys(value)) {
      assertValidUnicode(key);
      assertCanonicalDomain(value[key], ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Serializes a JSON value with recursively sorted object keys.
 *
 * The result follows the RFC 8785 rules used by this protocol: ECMAScript
 * primitive serialization, UTF-16 property ordering, no insignificant
 * whitespace, and rejection of values that are not valid I-JSON.
 */
export function canonicalizeJson(value: unknown): string {
  assertCanonicalDomain(value, new Set());
  const serialized = canonicalize(value);
  if (serialized === undefined) {
    throw new TypeError("Canonical JSON serialization failed.");
  }
  return serialized;
}
