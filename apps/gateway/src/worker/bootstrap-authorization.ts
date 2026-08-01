export async function bootstrapTokensMatch(
  actual: unknown,
  expected: string | undefined,
): Promise<boolean> {
  const actualToken = tokenCandidate(actual);
  const expectedToken = tokenCandidate(expected);
  const [actualDigest, expectedDigest] = await Promise.all([
    digest(actualToken.value),
    digest(expectedToken.value),
  ]);

  let difference = 0;
  for (let index = 0; index < actualDigest.length; index += 1) {
    difference |= actualDigest[index]! ^ expectedDigest[index]!;
  }
  return actualToken.valid && expectedToken.valid && difference === 0;
}

function tokenCandidate(value: unknown): { valid: boolean; value: string } {
  if (typeof value !== "string") return { valid: false, value: "" };
  return {
    valid: value.length > 0,
    value,
  };
}

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
}
