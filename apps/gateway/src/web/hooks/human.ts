import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { ApiError } from "../api";

export function useSessionExpiryRecovery(error: unknown): void {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!(error instanceof ApiError) || error.status !== 401) return;
    void queryClient.invalidateQueries({ queryKey: ["human-state"] });
  }, [error, queryClient]);
}
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = title;
  }, [title]);
}

export function useHumanRealtime(enabled: boolean): void {
  const queryClient = useQueryClient();
  const reconnectTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let socket: WebSocket | undefined;
    let retryDelay = 500;

    const refreshAll = (): void => {
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: ["requests"] }),
        queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["push-config"] }),
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
      ]);
    };
    const connect = (): void => {
      if (stopped || socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CONNECTING) {
        return;
      }
      const url = new URL("/v1/human/events", window.location.href);
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(url);
      socket.onopen = () => {
        retryDelay = 500;
        refreshAll();
      };
      socket.onmessage = (event) => {
        let value: unknown;
        try {
          value = JSON.parse(String(event.data));
        } catch {
          return;
        }
        if (!value || typeof value !== "object") return;
        const message = value as { entity_id?: unknown; type?: unknown };
        if (message.type === "request.changed" && typeof message.entity_id === "string") {
          void Promise.all([
            queryClient.invalidateQueries({ queryKey: ["requests"] }),
            queryClient.invalidateQueries({ queryKey: ["request", message.entity_id] }),
          ]);
          return;
        }
        if (message.type === "requester-enrollment.changed") {
          void queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] });
          return;
        }
        if (message.type === "management.changed") {
          void queryClient.invalidateQueries({ queryKey: ["management"] });
          return;
        }
        if (message.type === "lock.changed") {
          void Promise.all([
            queryClient.invalidateQueries({ queryKey: ["human-state"] }),
            queryClient.invalidateQueries({ queryKey: ["requests"] }),
            queryClient.invalidateQueries({ queryKey: ["management"] }),
          ]);
          return;
        }
        if (message.type === "ready") refreshAll();
      };
      socket.onclose = (event) => {
        socket = undefined;
        if (stopped) return;
        if (event.code === 4401 || event.code === 4403) {
          void queryClient.invalidateQueries({ queryKey: ["human-state"] });
          return;
        }
        reconnectTimer.current = window.setTimeout(connect, retryDelay);
        retryDelay = Math.min(retryDelay * 2, 10_000);
      };
    };
    const handleOnline = (): void => connect();
    window.addEventListener("online", handleOnline);
    connect();
    return () => {
      stopped = true;
      window.removeEventListener("online", handleOnline);
      if (reconnectTimer.current !== undefined) window.clearTimeout(reconnectTimer.current);
      socket?.close(1000, "page_unmounted");
    };
  }, [enabled, queryClient, reconnectTimer]);
}
