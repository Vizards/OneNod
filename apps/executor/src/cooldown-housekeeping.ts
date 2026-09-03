import { safeExecutorErrorName } from "./executor-failure";

export type CooldownUpdateStage =
  | "record_rate_limit"
  | "record_success"
  | "release_probe";

interface BestEffortCooldownUpdate {
  operation: string;
  report?: (message: string) => void;
  stage: CooldownUpdateStage;
  update: () => void;
}

/**
 * Cooldown state protects the upstream from repeated 429 probes, but it is not
 * authorization state and must never replace an already-known operation result.
 */
export function runBestEffortCooldownUpdate({
  operation,
  report = console.error,
  stage,
  update,
}: BestEffortCooldownUpdate): void {
  try {
    update();
  } catch (error) {
    try {
      report(
        JSON.stringify({
          errorName: safeExecutorErrorName(error),
          event: "executor_onepassword_cooldown_update_failed",
          operation: safeOperation(operation),
          stage,
        }),
      );
    } catch {
      // Diagnostic reporting must not overturn the operation result either.
    }
  }
}

function safeOperation(value: string): string {
  return /^[a-z][a-z0-9.]{0,63}$/u.test(value) ? value : "unknown";
}
