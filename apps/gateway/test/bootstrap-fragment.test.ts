import assert from "node:assert/strict";
import test from "node:test";

import { consumeBootstrapFragment } from "../src/web/bootstrap-fragment.js";

function fixture(hash: string) {
  const replacements: string[] = [];
  const result = consumeBootstrapFragment(
    { hash, pathname: "/initialize", search: "?source=operator" },
    {
      replaceState(_data, _unused, url) {
        replacements.push(String(url));
      },
      state: { navigation: true },
    },
  );
  return { replacements, result };
}

test("consumes a UTF-8 base64url bootstrap token and strips the fragment", () => {
  const token = "correct horse battery staple 🔐";
  const encoded = Buffer.from(token, "utf8").toString("base64url");
  const { replacements, result } = fixture(`#bootstrap=${encoded}`);

  assert.deepEqual(result, { status: "ready", token });
  assert.deepEqual(replacements, ["/initialize?source=operator"]);
});

test("strips invalid fragments and never exposes a token", () => {
  const { replacements, result } = fixture("#bootstrap=%25not-base64url");

  assert.deepEqual(result, { status: "invalid" });
  assert.deepEqual(replacements, ["/initialize?source=operator"]);
  assert.equal("token" in result, false);
});

test("reports a missing fragment without mutating clean navigation", () => {
  const { replacements, result } = fixture("");

  assert.deepEqual(result, { status: "missing" });
  assert.deepEqual(replacements, []);
});

test("preserves request deep links for the application router", () => {
  const { replacements, result } = fixture("#request-018f6df1");

  assert.deepEqual(result, { status: "missing" });
  assert.deepEqual(replacements, []);
});

test("rejects duplicate bootstrap parameters after stripping them", () => {
  const { replacements, result } = fixture("#bootstrap=YQ&bootstrap=Yg");

  assert.deepEqual(result, { status: "invalid" });
  assert.deepEqual(replacements, ["/initialize?source=operator"]);
});

test("rejects fragments with any field outside the exact one-time contract", () => {
  const encoded = Buffer.from("bootstrap-token", "utf8").toString("base64url");
  for (const hash of [
    `#source=operator&bootstrap=${encoded}`,
    `#bootstrap=${encoded}&source=operator`,
    `#BOOTSTRAP=${encoded}`,
  ]) {
    const { replacements, result } = fixture(hash);
    assert.deepEqual(result, { status: "invalid" });
    assert.deepEqual(replacements, ["/initialize?source=operator"]);
  }
});
