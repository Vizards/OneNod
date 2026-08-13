import assert from "node:assert/strict";
import test from "node:test";

import {
  assertLegacyAuthorizationDurationMatches,
  GatewayHttpError,
  readDecisionVerifyBody,
} from "../src/worker/approval-http.js";

function verifyRequest(
  authorizationDuration?: "4-hours" | "12-hours",
): Request {
  return new Request("https://gateway.example/verify", {
    body: JSON.stringify({
      ...(authorizationDuration
        ? { authorization_duration: authorizationDuration }
        : {}),
      challenge_id: "challenge-a",
      decision: "approve",
      response: { id: "credential-a" },
    }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
}

test("new approval clients may omit authorization duration at verify", async () => {
  const body = await readDecisionVerifyBody(verifyRequest(), {
    allowLegacyAuthorizationDuration: true,
  });

  assert.equal(body.authorization_duration, undefined);
});

test("alpha.20 approval verify may repeat its challenge-bound duration", async () => {
  const body = await readDecisionVerifyBody(verifyRequest("4-hours"), {
    allowLegacyAuthorizationDuration: true,
  });

  assert.equal(body.authorization_duration, "4-hours");
  assert.doesNotThrow(() =>
    assertLegacyAuthorizationDurationMatches(
      body.authorization_duration,
      "4-hours",
    ),
  );
});

test("legacy duration remains forbidden on non-approval decision endpoints", async () => {
  await assert.rejects(
    readDecisionVerifyBody(verifyRequest("4-hours")),
    (error: unknown) =>
      error instanceof GatewayHttpError && error.code === "request_schema_invalid",
  );
});

test("approval verify rejects a duration not bound into its challenge", () => {
  assert.throws(
    () => assertLegacyAuthorizationDurationMatches("12-hours", "4-hours"),
    (error: unknown) =>
      error instanceof GatewayHttpError &&
      error.code === "authorization_duration_mismatch" &&
      error.status === 400,
  );
  assert.throws(
    () => assertLegacyAuthorizationDurationMatches("4-hours", undefined),
    (error: unknown) =>
      error instanceof GatewayHttpError &&
      error.code === "authorization_duration_mismatch" &&
      error.status === 400,
  );
});
