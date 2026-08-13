import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";

import {
  authorizeBootstrapToken,
  beginBootstrapRegistration,
  beginDeviceRegistration,
  beginHumanSession,
  verifyBootstrapRegistration,
  verifyDeviceRegistration,
  verifyHumanSession,
  type DeviceRegistrationInput,
} from "../api";
import { consumeBootstrapFragment } from "../bootstrap-fragment";
import { ActionError, HumanGateCard } from "../components/common";
import {
  deviceProofMessage,
  getOrCreateDeviceIdentity,
  suggestedDeviceDetails,
} from "../device-identity";
import { usePageTitle } from "../hooks/human";

export function BootstrapPage() {
  usePageTitle("Initialize OneNod owner · OneNod");
  const queryClient = useQueryClient();
  const bootstrapToken = useRef<string | undefined>(
    bootstrapFragmentState.value.status === "ready"
      ? bootstrapFragmentState.value.token
      : undefined,
  );
  const [bootstrapStatus] = useState(bootstrapFragmentState.value.status);
  const [authorized, setAuthorized] = useState(false);
  const registration = useMutation({
    mutationFn: async () => {
      if (!authorized) {
        if (!bootstrapToken.current) {
          throw new Error("The one-time initialization link is missing or invalid.");
        }
        await authorizeBootstrapToken(bootstrapToken.current);
        bootstrapToken.current = undefined;
        bootstrapFragmentState.value = { status: "missing" };
        setAuthorized(true);
      }
      const challenge = await beginBootstrapRegistration();
      const response = await startRegistration({ optionsJSON: challenge.options });
      return verifyBootstrapRegistration(challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["human-state"] });
    },
  });

  return (
    <HumanGateCard eyebrow="Secure bootstrap" title="Register the primary passkey">
      <p className="text-sm leading-6 text-secondary">
        This is the one-time initialization for this approval gateway.
        WebAuthn and your chosen passkey provider create the credential; the private key stays
        with that provider and the gateway stores only the public key.
      </p>
      {bootstrapStatus === "ready" ? (
        <p className="mt-5 rounded-card border border-subtle bg-muted p-4 text-sm leading-6 text-secondary">
          One-time initialization link accepted. Its secret fragment has already been removed
          from the address bar and exists only in this page memory.
        </p>
      ) : (
        <div className="mt-5 rounded-card border border-danger-border bg-danger-muted p-4 text-sm leading-6 text-danger-text">
          {bootstrapStatus === "missing"
            ? "This page was opened without its one-time initialization link. Return to the operator setup flow and open the complete URL it provides."
            : "This one-time initialization link is invalid. Return to the operator setup flow and generate a new deployment plan."}
        </div>
      )}
      {authorized ? (
        <div className="mt-4 rounded-card border border-success-border bg-success-muted p-4 text-sm text-success">
          Setup code accepted. Complete passkey registration within two minutes.
        </div>
      ) : null}
      {registration.isError ? (
        <ActionError error={registration.error} onDismiss={() => registration.reset()} />
      ) : null}
      <button
        type="button"
        disabled={
          registration.isPending ||
          (!authorized && bootstrapStatus !== "ready")
        }
        onClick={() => registration.mutate()}
        className={`mt-6 h-12 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-60 ${registration.isPending ? "cursor-wait" : "disabled:cursor-not-allowed"}`}
      >
        {registration.isPending
          ? "Waiting for passkey provider…"
          : authorized
            ? "Register passkey"
            : "Authorize and register passkey"}
      </button>
    </HumanGateCard>
  );
}

export function LoginPage() {
  usePageTitle("Sign in to approvals · OneNod");
  const queryClient = useQueryClient();
  const login = useMutation({
    mutationFn: performHumanLogin,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["human-state"] });
    },
  });

  return (
    <HumanGateCard eyebrow="Human session" title="Open the approval queue">
      <p className="text-sm leading-6 text-secondary">
        Approval details are never public. Use a registered passkey to establish a viewing session.
        Every approval or rejection still requires fresh passkey verification.
      </p>
      {login.isError ? <ActionError error={login.error} onDismiss={() => login.reset()} /> : null}
      <button
        type="button"
        disabled={login.isPending}
        onClick={() => login.mutate()}
        className="mt-6 h-12 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:cursor-wait disabled:opacity-60"
      >
        {login.isPending ? "Waiting for passkey provider…" : "Sign in with a passkey"}
      </button>
    </HumanGateCard>
  );
}

export function DeviceSetupPage() {
  usePageTitle("Register approval device · OneNod");
  const queryClient = useQueryClient();
  const suggested = suggestedDeviceDetails();
  const [label, setLabel] = useState(suggested.label);

  const registration = useMutation({
    mutationFn: async () => {
      const identity = await getOrCreateDeviceIdentity();
      const input: DeviceRegistrationInput = {
        device_id: identity.deviceId,
        label,
        platform: suggested.platform,
        public_key: identity.publicKey,
      };
      const challenge = await beginDeviceRegistration(input);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      const signature = await identity.sign(
        deviceProofMessage(
          "device_registration",
          challenge.challenge_id,
          challenge.device_challenge,
          identity.deviceId,
        ),
      );
      return verifyDeviceRegistration(challenge.challenge_id, signature, response);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["human-state"] });
    },
  });

  return (
    <HumanGateCard
      eyebrow="Approval device"
      title="Register this approval device"
    >
      <p className="text-sm leading-6 text-secondary">
        Your passkey proves your human identity. This PWA also creates a non-exportable local device key so this installation can be identified and revoked independently.
      </p>
      <label className="mt-5 block text-xs text-secondary" htmlFor="device-label">
        Device name
      </label>
      <input
        id="device-label"
        value={label}
        maxLength={80}
        onChange={(event) => setLabel(event.target.value)}
        className="mt-2 h-11 w-full rounded-control border border-subtle bg-background px-3 text-sm"
      />
      <div className="mt-4 rounded-card border border-subtle bg-muted p-4 text-sm leading-5 text-secondary">
        Any registered passkey may authorize this installation. No approval from another device is required.
      </div>
      {registration.isError ? (
        <ActionError error={registration.error} onDismiss={() => registration.reset()} />
      ) : null}
      <button
        type="button"
        disabled={!label.trim() || registration.isPending}
        onClick={() => registration.mutate()}
        className="mt-6 h-12 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-60"
      >
        {registration.isPending ? "Waiting for passkey provider…" : "Register with passkey"}
      </button>
    </HumanGateCard>
  );
}

async function performHumanLogin(): Promise<{
  csrf_token: string;
  device_trusted: boolean;
  ok: true;
}> {
  const identity = await getOrCreateDeviceIdentity();
  const challenge = await beginHumanSession(identity.deviceId);
  const response = await startAuthentication({ optionsJSON: challenge.options });
  const signature = challenge.device_trusted
    ? await identity.sign(
        deviceProofMessage(
          "human_session",
          challenge.challenge_id,
          challenge.device_challenge,
          identity.deviceId,
        ),
      )
    : undefined;
  return verifyHumanSession(challenge.challenge_id, response, signature);
}

const bootstrapFragmentState = {
  value: consumeBootstrapFragment(window.location, window.history),
};
