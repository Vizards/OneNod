import { useEffect, useMemo, useRef, useState } from "react";

export interface ExpiryDeadline {
  expiresAt: string;
  id: string;
}

export function useServerClock(
  serverTime: string | undefined,
  onVisible?: () => void,
): number {
  const visibleCallback = useRef(onVisible);
  visibleCallback.current = onVisible;
  const anchor = useMemo(() => {
    const parsed = serverTime ? Date.parse(serverTime) : Number.NaN;
    return {
      monotonic: performance.now(),
      server: Number.isFinite(parsed) ? parsed : Date.now(),
    };
  }, [serverTime]);
  const [sample, setSample] = useState(() => performance.now());

  useEffect(() => {
    let interval: number | undefined;
    const tick = (): void => setSample(performance.now());
    const start = (): void => {
      if (interval !== undefined || document.hidden) return;
      tick();
      interval = window.setInterval(tick, 1_000);
    };
    const stop = (): void => {
      if (interval === undefined) return;
      window.clearInterval(interval);
      interval = undefined;
    };
    const handleVisibility = (): void => {
      if (document.hidden) {
        stop();
        return;
      }
      start();
      visibleCallback.current?.();
    };
    document.addEventListener("visibilitychange", handleVisibility);
    start();
    return () => {
      stop();
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [anchor]);

  return anchor.server + Math.max(0, sample - anchor.monotonic);
}

export function useExpiryRefresh(
  deadlines: readonly ExpiryDeadline[],
  now: number,
  refresh: () => void,
): void {
  const refreshed = useRef(new Set<string>());
  const refreshCallback = useRef(refresh);
  refreshCallback.current = refresh;

  useEffect(() => {
    const activeIds = new Set(deadlines.map((deadline) => deadline.id));
    for (const id of refreshed.current) {
      if (!activeIds.has(id)) refreshed.current.delete(id);
    }
    let crossed = false;
    for (const deadline of deadlines) {
      const expiresAt = Date.parse(deadline.expiresAt);
      if (
        Number.isFinite(expiresAt) &&
        expiresAt <= now &&
        !refreshed.current.has(deadline.id)
      ) {
        refreshed.current.add(deadline.id);
        crossed = true;
      }
    }
    if (crossed) refreshCallback.current();
  }, [deadlines, now]);
}
