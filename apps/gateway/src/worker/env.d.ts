import type { ApprovalCoordinator } from "./approval-coordinator";

declare global {
  interface Env {
    APP_ENV: "dev" | "prod";
    APPROVALS: DurableObjectNamespace<ApprovalCoordinator>;
    ASSETS: Fetcher;
    BOOTSTRAP_TOKEN?: string;
    EXECUTOR_AUTH_TOKEN?: string;
    EXECUTOR_SERVICE?: Fetcher;
    GATEWAY_MASTER_KEY?: string;
    ORIGIN: string;
    RP_ID: string;
    VAPID_PRIVATE_KEY?: string;
    VAPID_PUBLIC_KEY?: string;
    VAPID_SUBJECT?: string;
  }
}

export {};
