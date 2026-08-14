import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { Children, useState, type ReactNode } from "react";
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
import {
  formatDateTime,
  shortIdentifier,
  toErrorMessage,
} from "../utils/presentation";
import type { ManagementSection } from "./management-section";

export function ManagementPage() {
  usePageTitle("Approver management · OneNod");
  const queryClient = useQueryClient();
  const navigate = useNavigate({ from: "/management" });
  const { section } = useSearch({ from: "/management" });
  const management = useQuery({ queryFn: getHumanManagement, queryKey: ["management"] });
  const push = useQuery({ queryFn: getPushConfig, queryKey: ["push-config"] });
  const [pushError, setPushError] = useState<unknown>();
  const [pushPending, setPushPending] = useState(false);
  useSessionExpiryRecovery(management.error ?? push.error);

  async function enablePush(): Promise<void> {
    setPushPending(true);
    setPushError(undefined);
    try {
      if (
        !("serviceWorker" in navigator) ||
        !("PushManager" in window) ||
        !("Notification" in window)
      ) {
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
      if (permission !== "granted") {
        throw new Error("System notification permission was not granted.");
      }
      const registration = await readyPushServiceWorker();
      const existing = await settlePushStep(
        registration.pushManager.getSubscription(),
        undefined,
        "Checking the existing notification subscription took too long. Reload the page and try again.",
      );
      const subscription = existing ?? await settlePushStep(
        registration.pushManager.subscribe({
          applicationServerKey: ownedBytes(decodeBase64Url(push.data.public_key)),
          userVisibleOnly: true,
        }),
        undefined,
        "Creating the notification subscription took too long. Reload the page and try again.",
      );
      await settlePushStep(
        putPushSubscription(subscription.toJSON()),
        undefined,
        "Saving the notification subscription took too long. Reload the page and try again.",
      );
      queryClient.setQueryData(["push-config"], { ...push.data, enabled: true });
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
      queryClient.setQueryData(["push-config"], { ...push.data, enabled: false });
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
    return (
      <InlineError
        message={toErrorMessage(management.error)}
        onRetry={() => void management.refetch()}
      />
    );
  }

  const pushStatus = pushPending
    ? "Working…"
    : !push.data?.configured
      ? "Unavailable"
      : push.data.enabled
        ? "Enabled"
        : "Disabled";

  return (
    <section aria-labelledby="management-title">
      <header>
        <h1 id="management-title" className="text-2xl font-semibold tracking-[-0.03em]">
          Approver management
        </h1>
        <p className="mt-2 text-sm text-secondary">
          Manage approval devices, requester Macs, and owner passkeys.
        </p>
      </header>

      <section
        className="mt-6 flex min-h-14 flex-wrap items-center justify-between gap-x-4 rounded-card border border-subtle bg-surface px-3 py-1.5"
        aria-labelledby="push-title"
      >
        <div className="min-w-0">
          <h2 id="push-title" className="text-sm font-medium">System notifications</h2>
          <p className="truncate text-xs text-secondary">
            New-request alerts on this device · {pushStatus}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={Boolean(push.data?.enabled)}
          aria-label={`${push.data?.enabled ? "Disable" : "Enable"} system notifications`}
          disabled={pushPending || push.isPending || !push.data?.configured}
          onClick={() => void (push.data?.enabled ? disablePush() : enablePush())}
          className="relative h-11 w-12 shrink-0 disabled:opacity-50"
        >
          <span
            aria-hidden="true"
            className={`absolute inset-x-0 top-2 h-7 rounded-pill border transition-colors ${
              push.data?.enabled
                ? "border-success-border bg-success"
                : "border-subtle bg-muted"
            }`}
          >
            <span
              className={`absolute left-[3px] top-[3px] size-5 rounded-full bg-background transition-transform ${
                push.data?.enabled ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </span>
        </button>
        {pushError ? (
          <div className="basis-full pb-2">
            <ActionError
              error={pushError}
              onDismiss={() => setPushError(undefined)}
              compact
            />
          </div>
        ) : null}
      </section>

      <ManagementTabs
        counts={{
          approvers: management.data.devices.length,
          passkeys: management.data.credentials.length,
          requesters: management.data.requesters.length,
        }}
        onSelect={(nextSection) => {
          void navigate({ replace: true, search: { section: nextSection } });
        }}
        section={section}
      />

      {section === "approvers" ? (
        <ManagementPanel id="approvers-panel" label="Approval devices">
          <CompactList empty="No approval devices are registered.">
            {management.data.devices.map((device) => (
              <HumanDeviceRow
                key={device.id}
                device={device}
                canRevoke={management.data.devices.length > 1}
              />
            ))}
          </CompactList>
        </ManagementPanel>
      ) : null}

      {section === "requesters" ? (
        <ManagementPanel id="requesters-panel" label="Requester devices">
          <CompactList empty="No requester Macs are enrolled.">
            {management.data.requesters.map((requester) => (
              <RequesterRow key={requester.deviceId} requester={requester} />
            ))}
          </CompactList>
        </ManagementPanel>
      ) : null}

      {section === "passkeys" ? (
        <CredentialsPanel credentials={management.data.credentials} />
      ) : null}
    </section>
  );
}

function ManagementTabs({
  counts,
  onSelect,
  section,
}: {
  counts: Record<ManagementSection, number>;
  onSelect: (section: ManagementSection) => void;
  section: ManagementSection;
}) {
  const tabs: Array<{ label: string; value: ManagementSection }> = [
    { label: "Approvers", value: "approvers" },
    { label: "Requesters", value: "requesters" },
    { label: "Passkeys", value: "passkeys" },
  ];
  return (
    <div
      role="tablist"
      aria-label="Approver management sections"
      className="mt-6 grid grid-cols-3 border-b border-subtle"
    >
      {tabs.map((tab) => {
        const selected = section === tab.value;
        return (
          <button
            key={tab.value}
            id={`${tab.value}-tab`}
            type="button"
            role="tab"
            aria-controls={`${tab.value}-panel`}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onSelect(tab.value)}
            onKeyDown={(event) => {
              const currentIndex = tabs.findIndex((candidate) => candidate.value === tab.value);
              const targetIndex = event.key === "ArrowRight"
                ? (currentIndex + 1) % tabs.length
                : event.key === "ArrowLeft"
                  ? (currentIndex - 1 + tabs.length) % tabs.length
                  : event.key === "Home"
                    ? 0
                    : event.key === "End"
                      ? tabs.length - 1
                      : -1;
              if (targetIndex < 0) return;
              event.preventDefault();
              onSelect(tabs[targetIndex]!.value);
              const controls = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
                '[role="tab"]',
              );
              controls?.[targetIndex]?.focus();
            }}
            className={`relative min-h-12 px-1 text-sm ${
              selected ? "text-foreground" : "text-secondary"
            }`}
          >
            {tab.label}{" "}
            <span className="font-mono text-xs tabular-nums">{counts[tab.value]}</span>
            {selected ? (
              <span aria-hidden="true" className="absolute inset-x-2 -bottom-px h-px bg-foreground" />
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

function ManagementPanel({
  children,
  id,
  label,
}: {
  children: ReactNode;
  id: string;
  label: string;
}) {
  return (
    <section
      id={id}
      role="tabpanel"
      aria-labelledby={`${id.replace("-panel", "")}-tab`}
      className="mt-4"
    >
      <h2 className="sr-only">{label}</h2>
      {children}
    </section>
  );
}

function CompactList({
  children,
  empty,
}: {
  children: ReactNode;
  empty: string;
}) {
  if (Children.count(children) === 0) {
    return <p className="border-y border-subtle py-6 text-sm text-secondary">{empty}</p>;
  }
  return <ul className="divide-y divide-subtle border-y border-subtle">{children}</ul>;
}

function RequesterRow({ requester }: { requester: RequesterSummary }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [displayName, setDisplayName] = useState(requester.displayName);
  const rename = useMutation({
    mutationFn: async (nextDisplayName: string) => {
      const challenge = await beginRequesterRename(requester.deviceId, nextDisplayName);
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
        queryClient.invalidateQueries({ queryKey: ["authorization-summary"] }),
      ]);
    },
  });
  useSessionExpiryRecovery(rename.error ?? revoke.error);
  const normalizedName = displayName.trim();

  return (
    <li>
      <details className="group">
        <summary className="flex min-h-16 cursor-pointer list-none items-center gap-3 px-1 marker:content-none">
          <div className="min-w-0 flex-1">
            <h3 className="truncate text-sm font-medium">{requester.displayName}</h3>
            <p className="mt-1 truncate font-mono text-xs text-secondary">
              {shortIdentifier(requester.publicKeyFingerprint)} · enrolled {formatDateTime(requester.createdAt)}
            </p>
          </div>
          <RowChevron />
        </summary>
        <div className="border-t border-subtle px-1 pb-4 pt-3">
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
                className="mt-2 h-11 w-full rounded-control border border-subtle bg-background px-3 text-sm outline-none focus:border-focus"
              />
            </div>
          ) : null}
          <dl className={`${editing ? "mt-4" : ""} grid gap-3 text-xs`}>
            <ManagementFact label="Device ID" value={requester.deviceId} />
            <ManagementFact label="Fingerprint" value={requester.publicKeyFingerprint} />
            <ManagementFact label="Enrolled" value={formatDateTime(requester.createdAt)} />
          </dl>
          <div className="mt-4 grid grid-cols-2 gap-2 sm:flex sm:justify-end">
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
                  className="h-11 rounded-control border border-subtle px-3 text-sm disabled:opacity-40"
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
                  className="h-11 rounded-control bg-foreground px-3 text-sm text-background disabled:opacity-40"
                >
                  {rename.isPending ? "Verifying…" : "Save name"}
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  disabled={revoke.isPending}
                  onClick={() => setEditing(true)}
                  className="h-11 rounded-control border border-subtle px-3 text-sm disabled:opacity-40"
                >
                  Rename
                </button>
                <button
                  type="button"
                  disabled={revoke.isPending}
                  onClick={() => revoke.mutate()}
                  className="h-11 rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40"
                >
                  {revoke.isPending ? "Verifying…" : "Revoke"}
                </button>
              </>
            )}
          </div>
          {rename.isError ? (
            <ActionError error={rename.error} onDismiss={() => rename.reset()} compact />
          ) : null}
          {revoke.isError ? (
            <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
          ) : null}
        </div>
      </details>
    </li>
  );
}

function HumanDeviceRow({
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
  useSessionExpiryRecovery(revoke.error);
  return (
    <li>
      <details className="group">
        <summary className="flex min-h-16 cursor-pointer list-none items-center gap-3 px-1 marker:content-none">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <h3 className="truncate text-sm font-medium">{device.label}</h3>
              {device.current ? (
                <span className="shrink-0 text-xs text-secondary">This device</span>
              ) : null}
            </div>
            <p className="mt-1 truncate text-xs text-secondary">
              {device.platform} · active {formatDateTime(device.lastSeenAt)}
              {device.pushEnabled ? " · notifications on" : ""}
            </p>
          </div>
          <RowChevron />
        </summary>
        <div className="border-t border-subtle px-1 pb-4 pt-3">
          <dl className="grid gap-3 text-xs">
            <ManagementFact label="Created" value={formatDateTime(device.createdAt)} />
            <ManagementFact label="Last active" value={formatDateTime(device.lastSeenAt)} />
            <ManagementFact label="Push" value={device.pushEnabled ? "Enabled" : "Disabled"} />
          </dl>
          <button
            type="button"
            disabled={!canRevoke || revoke.isPending}
            onClick={() => revoke.mutate()}
            className="mt-4 h-11 w-full rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40 sm:ml-auto sm:block sm:w-auto"
          >
            {revoke.isPending ? "Verifying…" : "Revoke device"}
          </button>
          {!canRevoke ? (
            <p className="mt-2 text-xs text-secondary">The last approval device cannot be revoked.</p>
          ) : null}
          {revoke.isError ? (
            <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
          ) : null}
        </div>
      </details>
    </li>
  );
}

function CredentialsPanel({ credentials }: { credentials: HumanCredentialSummary[] }) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
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
      setAdding(false);
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  useSessionExpiryRecovery(add.error);
  return (
    <section
      id="passkeys-panel"
      role="tabpanel"
      aria-labelledby="passkeys-tab"
      className="mt-4"
    >
      <div className="mb-3 flex items-center justify-end">
        <button
          type="button"
          aria-expanded={adding}
          onClick={() => setAdding((value) => !value)}
          className="h-11 rounded-control border border-subtle px-3 text-sm"
        >
          {adding ? "Cancel" : "Add passkey"}
        </button>
      </div>
      {adding ? (
        <div className="mb-4 grid min-w-0 gap-2 rounded-card border border-subtle bg-surface p-3 sm:grid-cols-[minmax(0,1fr)_auto]">
          <input
            value={label}
            maxLength={80}
            onChange={(event) => setLabel(event.target.value)}
            placeholder="Passkey label"
            aria-label="Passkey label"
            className="h-11 min-w-0 rounded-control border border-subtle bg-background px-3 text-sm"
          />
          <button
            type="button"
            disabled={!label.trim() || add.isPending}
            onClick={() => add.mutate()}
            className="h-11 rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-50"
          >
            {add.isPending ? "Registering…" : "Register passkey"}
          </button>
          {add.isError ? (
            <div className="sm:col-span-2">
              <ActionError error={add.error} onDismiss={() => add.reset()} compact />
            </div>
          ) : null}
        </div>
      ) : null}
      <CompactList empty="No owner passkeys are registered.">
        {credentials.map((credential) => (
          <HumanCredentialRow
            key={credential.id}
            credential={credential}
            canRevoke={credentials.length > 1}
          />
        ))}
      </CompactList>
    </section>
  );
}

function HumanCredentialRow({
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
        queryClient.invalidateQueries({ queryKey: ["authorization-summary"] }),
      ]);
    },
  });
  useSessionExpiryRecovery(revoke.error);
  return (
    <li>
      <details className="group">
        <summary className="flex min-h-16 cursor-pointer list-none items-center gap-3 px-1 marker:content-none">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <h3 className="truncate text-sm font-medium">{credential.label}</h3>
              {credential.current ? (
                <span className="shrink-0 text-xs text-secondary">Current</span>
              ) : null}
            </div>
            <p className="mt-1 truncate text-xs text-secondary">
              {portability} · last used {credential.lastUsedAt ? formatDateTime(credential.lastUsedAt) : "unknown"}
            </p>
          </div>
          <RowChevron />
        </summary>
        <div className="border-t border-subtle px-1 pb-4 pt-3">
          <dl className="grid gap-3 text-xs">
            <ManagementFact label="Created" value={formatDateTime(credential.createdAt)} />
            <ManagementFact
              label="Last used"
              value={credential.lastUsedAt ? formatDateTime(credential.lastUsedAt) : "Unknown"}
            />
            <ManagementFact label="Portability" value={portability} />
          </dl>
          <button
            type="button"
            disabled={!canRevoke || revoke.isPending}
            onClick={() => revoke.mutate()}
            className="mt-4 h-11 w-full rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40 sm:ml-auto sm:block sm:w-auto"
          >
            {revoke.isPending ? "Verifying…" : "Revoke passkey"}
          </button>
          {!canRevoke ? (
            <p className="mt-2 text-xs text-secondary">The last owner passkey cannot be revoked.</p>
          ) : null}
          {revoke.isError ? (
            <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
          ) : null}
        </div>
      </details>
    </li>
  );
}

function ManagementFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid min-w-0 grid-cols-[6.5rem_minmax(0,1fr)] gap-3">
      <dt className="text-secondary">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-foreground">{value}</dd>
    </div>
  );
}

function RowChevron() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="size-4 shrink-0 text-secondary transition-transform group-open:rotate-180"
      fill="none"
    >
      <path
        d="m4 6 4 4 4-4"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.5"
      />
    </svg>
  );
}
