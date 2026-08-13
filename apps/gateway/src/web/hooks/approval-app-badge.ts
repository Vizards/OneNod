import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";

import { getRequesterEnrollments, getRequests } from "../api";
import { effectiveStatus, isPast } from "../utils/presentation";

export function useApprovalAppBadge(enabled: boolean): void {
  const requests = useQuery({
    enabled,
    queryKey: ["requests"],
    queryFn: () => getRequests(undefined, true),
  });
  const enrollments = useQuery({
    enabled,
    queryKey: ["requester-enrollments"],
    queryFn: getRequesterEnrollments,
  });

  useEffect(() => {
    if (!enabled || !requests.isSuccess || !enrollments.isSuccess) return;
    const pendingRequests = requests.data.requests.filter(
      (request) => effectiveStatus(request) === "pending",
    ).length;
    const pendingEnrollments = enrollments.data.enrollments.filter(
      (enrollment) => enrollment.status === "pending" && !isPast(enrollment.expiresAt),
    ).length;
    void updateAppBadge(pendingRequests + pendingEnrollments);
  }, [enabled, enrollments.data, enrollments.isSuccess, requests.data, requests.isSuccess]);
}
async function updateAppBadge(pendingCount: number): Promise<void> {
  const badgeNavigator = navigator as Navigator & {
    clearAppBadge?: () => Promise<void>;
    setAppBadge?: (contents?: number) => Promise<void>;
  };
  try {
    if (pendingCount > 0 && typeof badgeNavigator.setAppBadge === "function") {
      await badgeNavigator.setAppBadge(pendingCount);
      return;
    }
    if (typeof badgeNavigator.clearAppBadge === "function") {
      await badgeNavigator.clearAppBadge();
      return;
    }
    if (typeof badgeNavigator.setAppBadge === "function") {
      await badgeNavigator.setAppBadge(0);
    }
  } catch {
    // The approval queue remains authoritative when the platform rejects badging.
  }
}
