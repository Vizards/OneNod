import assert from "node:assert/strict";
import test from "node:test";

import { projectStoredApplicationIdentity } from "../src/worker/application-identity.js";

test("terminal Activity retains a verified application identity", () => {
  assert.deepEqual(
    projectStoredApplicationIdentity({
      application_assurance: "verified-code-signature",
      application_principal_id: "principal-digest",
      application_principal_scheme: "macos-designated-requirement-v1",
      application_signer_name: "OpenAI OpCo, LLC",
      application_signing_identifier: "com.openai.codex",
      application_team_identifier: "2DC432GLL2",
    }),
    {
      assurance: "verified-code-signature",
      platform: "macos",
      principal_id: "principal-digest",
      principal_scheme: "macos-designated-requirement-v1",
      signer_name: "OpenAI OpCo, LLC",
      signing_identifier: "com.openai.codex",
      team_identifier: "2DC432GLL2",
    },
  );
});
