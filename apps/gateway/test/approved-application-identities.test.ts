import assert from "node:assert/strict";
import test from "node:test";

import {
  projectApplicationRecognition,
  recordApprovedApplicationIdentity,
} from "../src/worker/approved-application-identities.js";
import type { ApplicationIdentityColumns } from "../src/worker/approval-types.js";
import { approvalStorage } from "./support/sqlite-do-storage.js";

const VERIFIED_IDENTITY: ApplicationIdentityColumns = {
  application_assurance: "verified-code-signature",
  application_principal_id: "principal-a",
  application_principal_scheme: "macos-designated-requirement-v1",
  application_signer_name: "OpenAI OpCo, LLC",
  application_signing_identifier: "com.openai.codex",
  application_team_identifier: "2DC432GLL2",
};

test("only Passkey-approved verified application identities enter recognition history", () => {
  const { database, sql } = approvalStorage();
  assert.equal(
    recordApprovedApplicationIdentity(
      sql,
      {
        ...VERIFIED_IDENTITY,
        application_assurance: "unverified",
        application_principal_id: null,
        application_principal_scheme: null,
        application_signing_identifier: null,
      },
      100,
    ),
    false,
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS count FROM approved_application_identities")
      .get()?.count,
    0,
  );

  assert.equal(recordApprovedApplicationIdentity(sql, VERIFIED_IDENTITY, 200), true);
  assert.equal(
    recordApprovedApplicationIdentity(
      sql,
      { ...VERIFIED_IDENTITY, application_signer_name: "Updated signer label" },
      300,
    ),
    true,
  );
  assert.deepEqual(
    { ...database.prepare(
      `SELECT principal_scheme, principal_id, signing_identifier,
              team_identifier, signer_name, first_approved_at,
              last_approved_at, approval_count
       FROM approved_application_identities`,
    ).get() },
    {
      approval_count: 2,
      first_approved_at: 200,
      last_approved_at: 300,
      principal_id: "principal-a",
      principal_scheme: "macos-designated-requirement-v1",
      signer_name: "Updated signer label",
      signing_identifier: "com.openai.codex",
      team_identifier: "2DC432GLL2",
    },
  );
});

test("application recognition separates first approval, prior approval, and unverified", () => {
  assert.equal(
    projectApplicationRecognition({
      application_assurance: "verified-code-signature",
      application_approved_before: 0,
    }),
    "first-approval",
  );
  assert.equal(
    projectApplicationRecognition({
      application_assurance: "verified-code-signature",
      application_approved_before: 1,
    }),
    "approved-before",
  );
  assert.equal(
    projectApplicationRecognition({
      application_assurance: "unverified",
      application_approved_before: 1,
    }),
    "unverified",
  );
});
