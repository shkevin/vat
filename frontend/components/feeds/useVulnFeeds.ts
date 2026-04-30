"use client";

import { useCallback } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import {
  fetchVulnFeedRecords,
  fetchVulnFeedRuns,
  fetchVulnFeedSummary,
  triggerVulnFeedRefresh,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";

interface UseVulnFeedsParams {
  source?: string;
  severity?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export function useVulnFeeds(params?: UseVulnFeedsParams) {
  const { token, user } = useAuth();
  const queryClient = useQueryClient();
  const auth = { token: token ?? undefined, userEmail: user?.email };
  const isAdmin = user?.role === "admin";
  // Use a per-user cache scope. Including the JWT in queryKey leaks the
  // bearer to React Query DevTools / persistQueryClient and thrashes the
  // cache on every token rotation. The user id is stable across rotations.
  const userScope = user?.id ?? "anon";

  const summaryQuery = useQuery({
    queryKey: ["vuln-feeds-summary", userScope],
    enabled: Boolean(token || user?.email),
    queryFn: () => fetchVulnFeedSummary(auth),
    refetchInterval: 60_000,
  });

  const runsQuery = useQuery({
    queryKey: ["vuln-feeds-runs", userScope],
    enabled: Boolean(token || user?.email),
    queryFn: () => fetchVulnFeedRuns({ limit: 50 }, auth),
    refetchInterval: 60_000,
  });

  const recordsQuery = useQuery({
    queryKey: [
      "vuln-feeds-records",
      userScope,
      params?.source ?? "",
      params?.severity ?? "",
      params?.search ?? "",
      params?.limit ?? 50,
      params?.offset ?? 0,
    ],
    enabled: Boolean(token || user?.email),
    queryFn: () => fetchVulnFeedRecords(params, auth),
    placeholderData: (prev) => prev,
  });

  const refresh = useCallback(async () => {
    if (!isAdmin) throw new Error("Admin role required");
    await triggerVulnFeedRefresh({ use_celery: true }, auth);
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["vuln-feeds-summary"] }),
      queryClient.invalidateQueries({ queryKey: ["vuln-feeds-runs"] }),
      queryClient.invalidateQueries({ queryKey: ["vuln-feeds-records"] }),
    ]);
  }, [isAdmin, auth, queryClient]);

  return {
    isAdmin,
    summary: summaryQuery.data,
    runs: runsQuery.data?.runs ?? [],
    records: recordsQuery.data?.records ?? [],
    recordsTotal: recordsQuery.data?.total ?? 0,
    loading: summaryQuery.isLoading || runsQuery.isLoading || recordsQuery.isLoading,
    error:
      (summaryQuery.error as Error | null)?.message ??
      (runsQuery.error as Error | null)?.message ??
      (recordsQuery.error as Error | null)?.message ??
      null,
    refresh,
    refreshing:
      summaryQuery.isFetching || runsQuery.isFetching || recordsQuery.isFetching,
  };
}
