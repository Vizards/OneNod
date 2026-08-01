import assert from "node:assert/strict";
import test from "node:test";

import {
  WireCodecError,
  decodeClientId,
  decodeDetailedItemList,
  decodeItem,
  decodeResolvedSecret,
  encodeClientConfig,
  encodeClientId,
  encodeInvocation,
} from "../src/onepassword-wire.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const vaultId = "a".repeat(26);
const itemId = "b".repeat(26);
const fakeServiceAccountToken = `ops_${"c".repeat(64)}`;

test("client config follows the pinned Go Extism casing", () => {
  const config = JSON.parse(decoder.decode(encodeClientConfig(fakeServiceAccountToken))) as Record<
    string,
    unknown
  >;
  assert.equal(config.serviceAccountToken, fakeServiceAccountToken);
  assert.equal(config.programmingLanguage, "JS");
  assert.equal(config.sdkVersion, "0040101");
  assert.equal(config.account_name, null);
  assert.equal(Object.hasOwn(config, "accountName"), false);
});

test("client IDs retain the full uint64 decimal representation", () => {
  const clientId = decodeClientId(encoder.encode("18446744073709551615"));
  assert.equal(decoder.decode(encodeClientId(clientId)), "18446744073709551615");
  const invocation = decoder.decode(encodeInvocation(clientId, { kind: "vault.list" }));
  assert.match(invocation, /"clientId":18446744073709551615/);
  assert.throws(
    () => decodeClientId(encoder.encode("18446744073709551616")),
    WireCodecError,
  );
});

test("closed invocation map fixes method names and parameter casing", () => {
  const clientId = decodeClientId(encoder.encode("7"));
  const get = JSON.parse(
    decoder.decode(encodeInvocation(clientId, { kind: "item.get", vaultId, itemId })),
  ) as {
    invocation: {
      clientId: number;
      parameters: { name: string; parameters: Record<string, unknown> };
    };
  };
  assert.deepEqual(get, {
    invocation: {
      clientId: 7,
      parameters: {
        name: "ItemsGet",
        parameters: { vault_id: vaultId, item_id: itemId },
      },
    },
  });

});

test("production invocations support archived listing, raw create, and scoped field resolve", () => {
  const clientId = decodeClientId(encoder.encode("8"));
  const archivedList = invocation({
    includeArchived: true,
    kind: "item.list",
    vaultId,
  });
  assert.deepEqual(archivedList.parameters, {
    filters: [
      {
        content: { active: true, archived: true },
        type: "ByState",
      },
    ],
    vault_id: vaultId,
  });

  const rawCreate = invocation({
    kind: "item.create.raw",
    params: {
      category: "SecureNote",
      fields: [
        {
          fieldType: "Concealed",
          id: "token",
          sectionId: "gateway-fields",
          title: "Token",
          value: "dummy-value",
        },
      ],
      sections: [{ id: "gateway-fields", title: "Gateway fields" }],
      tags: ["onenod"],
      title: "Gateway item",
      vaultId,
    },
  });
  assert.equal(rawCreate.name, "ItemsCreate");
  assert.equal((rawCreate.parameters.params as { title: string }).title, "Gateway item");

  const resolve = invocation({
    fieldId: "api/token",
    itemId,
    kind: "secret.resolve",
    vaultId,
  });
  assert.deepEqual(resolve, {
    name: "SecretsResolve",
    parameters: {
      secret_reference: `op://${vaultId}/${itemId}/api%2Ftoken`,
    },
  });

  const sshPrivateKeyResolve = invocation({
    fieldId: "private key",
    itemId,
    kind: "ssh.private-key.resolve",
    vaultId,
  });
  assert.deepEqual(sshPrivateKeyResolve, {
    name: "SecretsResolve",
    parameters: {
      secret_reference: `op://${vaultId}/${itemId}/private%20key?ssh-format=openssh`,
    },
  });

  const details = decodeDetailedItemList(
    encoder.encode(
      JSON.stringify([
        {
          category: "SecureNote",
          id: itemId,
          state: "archived",
          tags: ["onenod"],
          title: "Gateway item",
          updatedAt: "2026-07-20T00:00:00.000Z",
          vaultId,
        },
      ]),
    ),
  );
  assert.equal(details[0]?.state, "archived");

  function invocation(operation: Parameters<typeof encodeInvocation>[1]) {
    const decoded = JSON.parse(decoder.decode(encodeInvocation(clientId, operation))) as {
      invocation: {
        parameters: { name: string; parameters: Record<string, unknown> };
      };
    };
    return decoded.invocation.parameters;
  }
});

test("wire decoders reject invalid UTF-8 and incomplete Item responses", () => {
  assert.throws(() => decodeResolvedSecret(Uint8Array.from([0xff])), WireCodecError);
  assert.throws(
    () => decodeItem(encoder.encode(JSON.stringify({ id: itemId, vaultId, version: 1 }))),
    WireCodecError,
  );
});

test("Item fields normalize the Go core's null or empty sectionId without weakening validation", () => {
  const item = {
    category: "Password",
    createdAt: "2026-07-20T00:00:00.000Z",
    document: null,
    fields: [
      {
        details: { passwordStrength: "GOOD" },
        fieldType: "Concealed",
        id: "password",
        sectionId: null,
        title: "password",
        value: "dummy-value",
      },
    ],
    files: [],
    id: itemId,
    notes: "",
    sections: [],
    tags: ["dummy"],
    title: "gateway-dummy-secret",
    updatedAt: "2026-07-20T00:00:00.000Z",
    vaultId,
    version: 1,
    websites: [],
  };

  const decoded = decodeItem(encoder.encode(JSON.stringify(item)));
  assert.equal(decoded.fields[0]?.id, "password");
  assert.equal(Object.hasOwn(decoded.fields[0]!, "sectionId"), false);
  assert.deepEqual(decoded.fields[0]?.details, { passwordStrength: "GOOD" });

  item.fields[0]!.sectionId = "" as never;
  const decodedEmpty = decodeItem(encoder.encode(JSON.stringify(item)));
  assert.equal(Object.hasOwn(decodedEmpty.fields[0]!, "sectionId"), false);

  item.sections = [{ id: "", title: "" }] as never;
  const decodedPlaceholder = decodeItem(encoder.encode(JSON.stringify(item)));
  assert.deepEqual(decodedPlaceholder.sections, []);
  item.sections = [];

  item.fields[0]!.sectionId = 42 as never;
  assert.throws(
    () => decodeItem(encoder.encode(JSON.stringify(item))),
    WireCodecError,
  );
});
