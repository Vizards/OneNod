import {
  canonicalizeJson,
  decodeBase64Url,
  type SshSignCreateRequest,
  type SshAuthorizationSessionRequest,
  type SshOperationRequest,
  type SshSignatureAlgorithm,
} from "@onenod/protocol";

import type { CatalogExecutorItem } from "./gateway-envelope.js";

export interface SshSignDescription {
  expectedVersion: number;
  fingerprint: string;
  itemId: string;
  itemTitle: string;
  signatureAlgorithm: SshSignatureAlgorithm;
  summary: Array<{ label: string; value: string }>;
}

export interface TrustedSshAuthorization {
  fingerprint: string;
  itemId: string;
  itemTitle: string;
  itemVersion: number;
}

export function parseSshSignRequest(value: unknown): SshSignCreateRequest {
  const body = record(value);
  assertExactKeys(body, [
    "action",
    "algorithm",
    ...("authorization_session" in body ? ["authorization_session"] : []),
    "client",
    "data",
    "expected_fingerprint",
    "expected_version",
    "idempotency_key",
    "item_id",
    "operation",
  ]);
  if (body.action !== "ssh.sign") throw new Error("unsupported_action");
  const data = boundedBase64Url(body.data, 64 * 1_024);
  return {
    action: "ssh.sign",
    algorithm: signatureAlgorithm(body.algorithm),
    ...("authorization_session" in body
      ? { authorization_session: sshAuthorizationSession(body.authorization_session) }
      : {}),
    client: body.client as SshSignCreateRequest["client"],
    data,
    expected_fingerprint: fingerprint(body.expected_fingerprint),
    expected_version: positiveInteger(body.expected_version, "expected_version"),
    idempotency_key: identifier(body.idempotency_key, "idempotency_key"),
    item_id: identifier(body.item_id, "item_id"),
    operation: sshOperation(body.operation),
  };
}

export function sshAuthorizationProofMaterial(
  body: SshSignCreateRequest,
): Uint8Array {
  if (!body.authorization_session) {
    throw new Error("ssh_authorization_session_missing");
  }
  const { proof: _proof, ...session } = body.authorization_session;
  return new TextEncoder().encode(
    canonicalizeJson({
      ...body,
      authorization_session: session,
    }),
  );
}

export function describeSshSign(
  body: SshSignCreateRequest,
  metadata: CatalogExecutorItem,
  payloadDigest: string,
): SshSignDescription {
  if (
    metadata.item_id !== body.item_id ||
    metadata.version !== body.expected_version
  ) {
    throw new Error("item_stale");
  }
  if (!metadata.ssh || metadata.ssh.fingerprint !== body.expected_fingerprint) {
    throw new Error("ssh_key_mismatch");
  }
  if (!algorithmMatchesKey(metadata.ssh.algorithm, body.algorithm)) {
    throw new Error("ssh_algorithm_mismatch");
  }
  return {
    expectedVersion: metadata.version,
    fingerprint: metadata.ssh.fingerprint,
    itemId: metadata.item_id,
    itemTitle: metadata.title,
    signatureAlgorithm: body.algorithm,
    summary: [
      { label: "Item", value: metadata.title },
      { label: "Version", value: String(metadata.version) },
      { label: "SSH key fingerprint", value: metadata.ssh.fingerprint },
      { label: "SSH key algorithm", value: metadata.ssh.algorithm },
      { label: "Signature algorithm", value: body.algorithm },
      { label: "Encrypted signing payload digest", value: payloadDigest },
      ...describeSshOperation(
        body.operation,
      ),
    ],
  };
}

export function describeAuthorizedSshSign(
  body: SshSignCreateRequest,
  authorization: TrustedSshAuthorization,
  payloadDigest: string,
): SshSignDescription {
  if (
    authorization.itemId !== body.item_id ||
    authorization.itemVersion !== body.expected_version ||
    authorization.fingerprint !== body.expected_fingerprint
  ) {
    throw new Error("ssh_authorization_mismatch");
  }
  return {
    expectedVersion: authorization.itemVersion,
    fingerprint: authorization.fingerprint,
    itemId: authorization.itemId,
    itemTitle: authorization.itemTitle,
    signatureAlgorithm: body.algorithm,
    summary: [
      { label: "Item", value: authorization.itemTitle },
      { label: "Version", value: String(authorization.itemVersion) },
      { label: "SSH key fingerprint", value: authorization.fingerprint },
      { label: "Signature algorithm", value: body.algorithm },
      { label: "Encrypted signing payload digest", value: payloadDigest },
      ...describeSshOperation(body.operation),
    ],
  };
}

export function sshSignExecutorBody(
  body: SshSignCreateRequest,
): Record<string, unknown> {
  return {
    algorithm: body.algorithm,
    data: body.data,
    expected_fingerprint: body.expected_fingerprint,
    expected_version: body.expected_version,
    item_id: body.item_id,
  };
}

function sshOperation(value: unknown): SshOperationRequest {
  const input = record(value);
  if (input.kind === "ssh.opaque-signature") {
    assertExactKeys(input, ["kind"]);
    return { kind: "ssh.opaque-signature" };
  }
  if (input.kind === "git.ssh-signature") {
    assertExactKeys(input, ["kind", "namespace"]);
    if (input.namespace !== "git") {
      throw new Error("git_signature_namespace_invalid");
    }
    return {
      kind: "git.ssh-signature",
      namespace: "git",
    };
  }
  if (input.kind !== "ssh.authentication") {
    throw new Error("ssh_operation_invalid");
  }
  assertExactKeys(input, [
    "authentication_method",
    "kind",
    "remote_username",
    ...("server_host_key_fingerprint" in input
      ? ["server_host_key_fingerprint"]
      : []),
    "session_binding",
    "service",
    "session_id_fingerprint",
  ]);
  if (
    input.authentication_method !== "publickey" &&
    input.authentication_method !== "publickey-hostbound-v00@openssh.com"
  ) {
    throw new Error("ssh_authentication_method_invalid");
  }
  if (input.service !== "ssh-connection") {
    throw new Error("ssh_service_invalid");
  }
  if (
    input.session_binding !== "verified" &&
    input.session_binding !== "unavailable"
  ) {
    throw new Error("ssh_session_binding_invalid");
  }
  const serverHostKeyFingerprint =
    input.server_host_key_fingerprint === undefined
      ? undefined
      : fingerprint(input.server_host_key_fingerprint);
  if (
    (input.session_binding === "verified") !==
    (serverHostKeyFingerprint !== undefined)
  ) {
    throw new Error("ssh_session_binding_invalid");
  }
  return {
    authentication_method: input.authentication_method,
    kind: "ssh.authentication",
    remote_username: identifier(input.remote_username, "remote_username"),
    ...(serverHostKeyFingerprint
      ? { server_host_key_fingerprint: serverHostKeyFingerprint }
      : {}),
    session_binding: input.session_binding,
    service: "ssh-connection",
    session_id_fingerprint: fingerprint(input.session_id_fingerprint),
  };
}

function sshAuthorizationSession(
  value: unknown,
): SshAuthorizationSessionRequest {
  const input = record(value);
  assertExactKeys(input, [
    "agent_instance_public_key",
    "proof",
    "scope_id",
    "scope_kind",
  ]);
  if (
    input.scope_kind !== "application" &&
    input.scope_kind !== "terminal-session"
  ) {
    throw new Error("ssh_authorization_scope_invalid");
  }
  const publicKey = boundedBase64Url(input.agent_instance_public_key, 32);
  const proof = boundedBase64Url(input.proof, 64);
  const scopeId = boundedBase64Url(input.scope_id, 32);
  if (
    decodeBase64Url(publicKey).byteLength !== 32 ||
    decodeBase64Url(proof).byteLength !== 64 ||
    decodeBase64Url(scopeId).byteLength !== 32
  ) {
    throw new Error("ssh_authorization_session_invalid");
  }
  return {
    agent_instance_public_key: publicKey,
    proof,
    scope_id: scopeId,
    scope_kind: input.scope_kind,
  };
}

function describeSshOperation(
  operation: SshOperationRequest,
): Array<{ label: string; value: string }> {
  if (operation.kind === "ssh.opaque-signature") {
    return [
      { label: "Operation", value: "Opaque SSH signature" },
      {
        label: "System-enforced effect",
        value: "Return one signature; never export the private key",
      },
    ];
  }
  if (operation.kind === "git.ssh-signature") {
    return [
      { label: "Operation", value: "Git SSH signature" },
      { label: "SSH signature namespace", value: operation.namespace },
      {
        label: "System-enforced effect",
        value: "Return one SSHSIG signature to Git; never export the private key",
      },
    ];
  }
  return [
    { label: "Operation", value: "SSH public-key authentication" },
    { label: "Remote username", value: operation.remote_username },
    { label: "SSH service", value: operation.service },
    { label: "Authentication method", value: operation.authentication_method },
    ...(operation.server_host_key_fingerprint
      ? [
          {
            label: "Session-bound server host key",
            value: operation.server_host_key_fingerprint,
          },
        ]
      : []),
    {
      label:
        operation.session_binding === "verified"
          ? "Verified SSH session"
          : "SSH session (server identity unavailable)",
      value: operation.session_id_fingerprint,
    },
    {
      label: "System-enforced effect",
      value: "Return one session-bound authentication signature; never export the private key",
    },
  ];
}

function algorithmMatchesKey(
  keyAlgorithm: string,
  signature: SshSignatureAlgorithm,
): boolean {
  if (keyAlgorithm === "ssh-rsa") {
    return signature === "rsa-sha2-256" || signature === "rsa-sha2-512";
  }
  return keyAlgorithm === signature;
}

function signatureAlgorithm(value: unknown): SshSignatureAlgorithm {
  if (
    value !== "ssh-ed25519" &&
    value !== "rsa-sha2-256" &&
    value !== "rsa-sha2-512"
  ) {
    throw new Error("ssh_algorithm_unsupported");
  }
  return value;
}

function fingerprint(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(value)
  ) {
    throw new Error("ssh_fingerprint_invalid");
  }
  return value;
}

function boundedBase64Url(value: unknown, maximumBytes: number): string {
  if (typeof value !== "string") throw new Error("ssh_data_invalid");
  let decoded: Uint8Array;
  try {
    decoded = decodeBase64Url(value);
  } catch {
    throw new Error("ssh_data_invalid");
  }
  if (decoded.byteLength === 0 || decoded.byteLength > maximumBytes) {
    throw new Error("ssh_data_invalid");
  }
  return value;
}

function assertExactKeys(body: Record<string, unknown>, expected: string[]): void {
  const keys = Object.keys(body).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error("request_schema_invalid");
  }
}

function identifier(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    hasForbiddenControl(value)
  ) {
    throw new Error(`${name}_invalid`);
  }
  return value;
}

function positiveInteger(value: unknown, name: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${name}_invalid`);
  }
  return value as number;
}

function hasForbiddenControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint < 0x20 || codePoint === 0x7f) return true;
  }
  return false;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("request_schema_invalid");
  }
  return value as Record<string, unknown>;
}
