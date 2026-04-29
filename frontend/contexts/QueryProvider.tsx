"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { setContainerAssetPathAliases } from "@/lib/containerRefNormalization";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api";

/** Cap the wait for /api/config/container-aliases so the app still renders if the
 * backend is briefly unreachable. Aliases default to "no rewrites" in that case,
 * which matches behavior prior to runtime fetching. */
const ALIAS_FETCH_TIMEOUT_MS = 1500;

async function primeContainerAliases(): Promise<void> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ALIAS_FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(`${API_BASE}/config/container-aliases`, {
      signal: ctrl.signal,
      credentials: "same-origin",
    });
    if (!resp.ok) return;
    const data = (await resp.json()) as { aliases?: string };
    setContainerAssetPathAliases(data.aliases ?? "");
  } catch {
    // Network error or timeout: keep whatever rules were primed at module load.
  } finally {
    clearTimeout(t);
  }
}

export function VATQueryProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            gcTime: 10 * 60_000,
            refetchOnWindowFocus: true,
            retry: 1,
          },
        },
      }),
  );

  // Wait for alias rules on the client so deriveAssets sees the same rules
  // the backend uses. SSR renders immediately (aliasesReady=true) since no
  // client-side asset derivation runs there.
  const [aliasesReady, setAliasesReady] = useState<boolean>(
    typeof window === "undefined",
  );

  useEffect(() => {
    let cancelled = false;
    primeContainerAliases().finally(() => {
      if (!cancelled) setAliasesReady(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!aliasesReady) return null;

  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}
