import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { decodeBase64Url } from "@onenod/protocol";

import { passkeyPortabilityLabel } from "../../passkey-identity";
import { ownedBytes } from "../../shared/owned-bytes";
import {
  authorizeCredentialRegistration,
  beginCredentialRegistration,
  beginCredentialRevoke,
  beginDeviceRevoke,
  beginRequesterRename,
  beginRequesterRevoke,
  deletePushSubscription,
  getHumanManagement,
  getPushConfig,
  putPushSubscription,
  verifyCredentialRegistration,
  verifyCredentialRevoke,
  verifyDeviceRevoke,
  verifyRequesterRename,
  verifyRequesterRevoke,
  type HumanCredentialSummary,
  type HumanDeviceSummary,
  type RequesterSummary,
} from "../api";
import { ActionError, InlineError, PagePanelSkeleton } from "../components/common";
import { usePageTitle, useSessionExpiryRecovery } from "../hooks/human";
import { readyPushServiceWorker, settlePushStep } from "../push-registration";
import { formatDateTime, toErrorMessage } from "../utils/presentation";

export function ManagementPage() {
  usePageTitle("Approver management · OneNod");
  const queryClient = useQueryClient();
  const management = useQuery({ queryFn: getHumanManagement, queryKey: ["management"] });
  const push = useQuery({ queryFn: getPushConfig, queryKey: ["push-config"] });
  const [pushError, setPushError] = useState<unknown>();
  const [pushPending, setPushPending] = useState(false);
  useSessionExpiryRecovery(management.error ?? push.error);

  async function enablePush(): Promise<void> {
    setPushPending(true);
    setPushError(undefined);
    try {
      if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
        throw new Error("This browser does not support Web Push.");
      }
      if (!push.data?.configured || !push.data.public_key) {
        throw new Error("The server has no VAPID key configured.");
      }
      const permission = await settlePushStep(
        Notification.requestPermission(),
        60_000,
        "Notification permission was not completed. Check the browser prompt and try again.",
      );
      if (permission !== "granted") throw new Error("System notification permission was not granted.");
      const registration = await readyPushServiceWorker();
      const existing = await settlePushStep(
        registration.pushManager.getSubscription(),
        undefined,
        "Checking the existing notification subscription took too long. Reload the page and try again.",
      );
      const subscription =
        existing ??
        (await settlePushStep(
          registration.pushManager.subscribe({
            applicationServerKey: ownedBytes(decodeBase64Url(push.data.public_key)),
            userVisibleOnly: true,
          }),
          undefined,
          "Creating the notification subscription took too long. Reload the page and try again.",
        ));
      await settlePushStep(
        putPushSubscription(subscription.toJSON()),
        undefined,
        "Saving the notification subscription took too long. Reload the page and try again.",
      );
      queryClient.setQueryData(["push-config"], {
        ...push.data,
        enabled: true,
      });
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: ["push-config"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
      ]).catch(() => undefined);
    } catch (error) {
      setPushError(error);
    } finally {
      setPushPending(false);
    }
  }

  async function disablePush(): Promise<void> {
    setPushPending(true);
    setPushError(undefined);
    try {
      await settlePushStep(
        deletePushSubscription(),
        undefined,
        "Disabling the server subscription took too long. Reload the page and try again.",
      );
      queryClient.setQueryData(["push-config"], {
        ...push.data,
        enabled: false,
      });
      const registration = await readyPushServiceWorker();
      const subscription = await settlePushStep(
        registration.pushManager.getSubscription(),
        undefined,
        "Checking the local notification subscription took too long. Reload the page and try again.",
      );
      if (subscription) {
        await settlePushStep(
          subscription.unsubscribe(),
          undefined,
          "Removing the local notification subscription took too long. Reload the page and try again.",
        );
      }
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: ["push-config"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
      ]).catch(() => undefined);
    } catch (error) {
      setPushError(error);
    } finally {
      setPushPending(false);
    }
  }

  if (management.isPending) return <PagePanelSkeleton />;
  if (management.isError) {
    return <InlineError message={toErrorMessage(management.error)} onRetry={() => void management.refetch()} />;
  }

  return (
    <section aria-labelledby="management-title">
      <p className="mb-2 font-mono text-xs uppercase tracking-[0.12em] text-secondary">
        Human control plane
      </p>
      <h1 id="management-title" className="text-2xl font-semibold tracking-[-0.03em]">
        Approver management
      </h1>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-secondary">
        A passkey verifies your human identity. A device key identifies one PWA installation. Revoking a device does not delete a passkey synced to other devices.
      </p>

      <section className="mt-10 rounded-card border border-subtle bg-surface p-5" aria-labelledby="push-title">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 id="push-title" className="text-base font-medium">System notifications on this device</h2>
            <p className="mt-2 text-sm leading-5 text-secondary">
              Notifications reveal only that a new request exists. They never show the item, field, or client observation on the lock screen.
            </p>
          </div>
          <button
            type="button"
            disabled={pushPending || push.isPending || !push.data?.configured}
            onClick={() => void (push.data?.enabled ? disablePush() : enablePush())}
            className="h-10 rounded-control border border-subtle bg-background px-4 text-sm font-medium disabled:opacity-50"
          >
            {pushPending ? "Working…" : push.data?.enabled ? "Disable notifications" : "Enable notifications"}
          </button>
        </div>
        {pushError ? <ActionError error={pushError} onDismiss={() => setPushError(undefined)} compact /> : null}
        {!push.data?.configured ? (
          <p className="mt-3 text-xs text-warning">The server has no VAPID key. Subscriptions remain unavailable until deployment setup is complete.</p>
        ) : null}
      </section>

      <section className="mt-10" aria-labelledby="devices-title">
        <div className="flex items-center justify-between gap-4">
          <h2 id="devices-title" className="text-base font-medium">Approval devices</h2>
          <span className="font-mono text-xs text-secondary">{management.data.devices.length} devices</span>
        </div>
        <ul className="mt-4 grid gap-3">
          {management.data.devices.map((device) => (
            <HumanDeviceCard
              key={device.id}
              device={device}
              canRevoke={management.data.devices.length > 1}
            />
          ))}
        </ul>
      </section>

      <section className="mt-10" aria-labelledby="requesters-title">
        <div className="flex items-center justify-between gap-4">
          <h2 id="requesters-title" className="text-base font-medium">
            Requester devices
          </h2>
          <span className="font-mono text-xs text-secondary">
            {management.data.requesters.length} requesters
          </span>
        </div>
        <p className="mt-2 text-sm leading-5 text-secondary">
          These Origin-scoped public keys identify enrolled Macs that may submit
          approval requests. They do not identify an application or authorize
          approval. Revoking one immediately blocks new requests, status polling,
          and result consumption from that requester.
        </p>
        <ul className="mt-4 grid gap-3">
          {management.data.requesters.map((requester) => (
            <RequesterCard key={requester.deviceId} requester={requester} />
          ))}
        </ul>
      </section>

      <CredentialsSection credentials={management.data.credentials} />
    </section>
  );
}
function RequesterCard({ requester }: { requester: RequesterSummary }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [displayName, setDisplayName] = useState(requester.displayName);
  const rename = useMutation({
    mutationFn: async (nextDisplayName: string) => {
      const challenge = await beginRequesterRename(
        requester.deviceId,
        nextDisplayName,
      );
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyRequesterRename(
        requester.deviceId,
        challenge.challenge_id,
        response,
      );
    },
    onSuccess: async () => {
      setEditing(false);
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  const revoke = useMutation({
    mutationFn: async () => {
      const challenge = await beginRequesterRevoke(requester.deviceId);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyRequesterRevoke(
        requester.deviceId,
        challenge.challenge_id,
        response,
      );
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] }),
      ]);
    },
  });
  useSessionExpiryRecovery(rename.error ?? revoke.error);
  const normalizedName = displayName.trim();

  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        {editing ? (
          <div className="max-w-sm">
            <label htmlFor={`requester-name-${requester.deviceId}`} className="text-xs text-secondary">
              Requester device name
            </label>
            <input
              id={`requester-name-${requester.deviceId}`}
              autoFocus
              maxLength={80}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              className="mt-2 h-10 w-full rounded-control border border-subtle bg-background px-3 text-sm outline-none focus:border-focus"
            />
          </div>
        ) : (
          <h3 className="font-medium">{requester.displayName}</h3>
        )}
        <p className="mt-2 text-xs text-secondary">
          Enrolled {formatDateTime(requester.createdAt)}
        </p>
        <p className="mt-3 max-w-full break-all font-mono text-[11px] text-secondary">
          Device {requester.deviceId}
        </p>
        <p className="mt-2 max-w-full break-all font-mono text-[11px] text-secondary">
          Fingerprint {requester.publicKeyFingerprint}
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:flex">
        {editing ? (
          <>
            <button
              type="button"
              disabled={rename.isPending}
              onClick={() => {
                setDisplayName(requester.displayName);
                setEditing(false);
                rename.reset();
              }}
              className="h-10 rounded-control border border-subtle px-3 text-sm disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={
                rename.isPending ||
                normalizedName.length === 0 ||
                normalizedName === requester.displayName
              }
              onClick={() => rename.mutate(normalizedName)}
              className="h-10 rounded-control bg-foreground px-3 text-sm text-background disabled:opacity-40"
            >
              {rename.isPending ? "Verifying…" : "Save name"}
            </button>
          </>
        ) : (
          <button
            type="button"
            disabled={revoke.isPending}
            onClick={() => setEditing(true)}
            className="h-10 rounded-control border border-subtle px-3 text-sm disabled:opacity-40"
          >
            Rename device
          </button>
        )}
        {!editing ? (
          <button
            type="button"
            disabled={revoke.isPending}
            onClick={() => revoke.mutate()}
            className="h-10 rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40"
          >
            {revoke.isPending ? "Verifying…" : "Revoke requester"}
          </button>
        ) : null}
      </div>
      {rename.isError ? (
        <ActionError error={rename.error} onDismiss={() => rename.reset()} compact />
      ) : null}
      {revoke.isError ? (
        <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
      ) : null}
    </li>
  );
}

function HumanDeviceCard({
  canRevoke,
  device,
}: {
  canRevoke: boolean;
  device: HumanDeviceSummary;
}) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: async () => {
      const challenge = await beginDeviceRevoke(device.id);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyDeviceRevoke(device.id, challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
      ]);
    },
  });
  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-medium">{device.label}</h3>
          {device.current ? <span className="rounded-pill bg-muted px-2 py-1 text-xs text-secondary">Current device</span> : null}
          {device.pushEnabled ? <span className="rounded-pill bg-success-muted px-2 py-1 text-xs text-success">Push enabled</span> : null}
        </div>
        <p className="mt-2 text-xs text-secondary">
          {device.platform} · last active {formatDateTime(device.lastSeenAt)}
        </p>
      </div>
      <button
        type="button"
        disabled={!canRevoke || revoke.isPending}
        onClick={() => revoke.mutate()}
        className="h-10 w-full rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40 sm:w-auto"
      >
        {revoke.isPending ? "Verifying…" : "Revoke device"}
      </button>
      {revoke.isError ? <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact /> : null}
    </li>
  );
}

function CredentialsSection({ credentials }: { credentials: HumanCredentialSummary[] }) {
  const queryClient = useQueryClient();
  const [label, setLabel] = useState("");
  const add = useMutation({
    mutationFn: async () => {
      const authorization = await beginCredentialRegistration(label);
      const authorizationResponse = await startAuthentication({ optionsJSON: authorization.options });
      const registration = await authorizeCredentialRegistration(
        authorization.challenge_id,
        authorizationResponse,
      );
      const registrationResponse = await startRegistration({ optionsJSON: registration.options });
      return verifyCredentialRegistration(registration.challenge_id, registrationResponse);
    },
    onSuccess: async () => {
      setLabel("");
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  return (
    <section className="mt-10" aria-labelledby="credentials-title">
      <h2 id="credentials-title" className="text-base font-medium">Owner passkeys</h2>
      <p className="mt-2 text-sm leading-5 text-secondary">
        Passkeys verify the OneNod owner. A synced passkey can serve multiple devices;
        PWA installations are registered and revoked separately below.
      </p>
      <p className="mt-2 text-xs leading-5 text-secondary">
        The label is stored by OneNod for management only. The passkey account is
        always OneNod owner.
      </p>
      <div className="mt-4 grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
        <input
          value={label}
          maxLength={80}
          onChange={(event) => setLabel(event.target.value)}
          placeholder="Passkey label (for example, 1Password)"
          className="h-11 min-w-0 flex-1 rounded-control border border-subtle bg-background px-3 text-sm"
        />
        <button
          type="button"
          disabled={!label.trim() || add.isPending}
          onClick={() => add.mutate()}
          className="h-11 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-50 sm:w-auto"
        >
          {add.isPending ? "Registering…" : "Add passkey"}
        </button>
      </div>
      {add.isError ? <ActionError error={add.error} onDismiss={() => add.reset()} compact /> : null}
      <ul className="mt-4 grid gap-3">
        {credentials.map((credential) => (
          <HumanCredentialCard
            key={credential.id}
            credential={credential}
            canRevoke={credentials.length > 1}
          />
        ))}
      </ul>
    </section>
  );
}

function HumanCredentialCard({
  canRevoke,
  credential,
}: {
  canRevoke: boolean;
  credential: HumanCredentialSummary;
}) {
  const queryClient = useQueryClient();
  const portability = passkeyPortabilityLabel(
    credential.deviceType,
    credential.backedUp,
  );
  const revoke = useMutation({
    mutationFn: async () => {
      const challenge = await beginCredentialRevoke(credential.id);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyCredentialRevoke(credential.id, challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
      ]);
    },
  });
  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-medium">{credential.label}</h3>
          {credential.current ? <span className="rounded-pill bg-muted px-2 py-1 text-xs text-secondary">Current passkey</span> : null}
          <span className="rounded-pill bg-muted px-2 py-1 text-xs text-secondary">{portability}</span>
        </div>
        <p className="mt-2 text-xs text-secondary">
          Added {formatDateTime(credential.createdAt)} · last used {credential.lastUsedAt ? formatDateTime(credential.lastUsedAt) : "Unknown"}
        </p>
      </div>
      <button
        type="button"
        disabled={!canRevoke || revoke.isPending}
        onClick={() => revoke.mutate()}
        className="h-10 w-full rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40 sm:w-auto"
      >
        {revoke.isPending ? "Verifying…" : "Revoke passkey"}
      </button>
      {revoke.isError ? <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact /> : null}
    </li>
  );
}
