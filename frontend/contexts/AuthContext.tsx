"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { fetchMe, logoutSession } from "@/lib/api";
import { setOnUnauthorized } from "@/lib/onUnauthorized";

// User profile is cached in localStorage purely to avoid a render flash
// while /api/auth/me roundtrips. The JWT itself never lands here.
const STORAGE_KEY = "vat-user";
// Legacy keys from pre-cookie sessions. We never read them anymore;
// purge on bootstrap so old browsers stop carrying around a stale JWT
// in DOM-readable storage.
const LEGACY_TOKEN_KEY = "vat-token";

export interface VATUser {
  id: string;
  email: string;
  role: string;
  tenant_id: string | null;
}

interface AuthContextValue {
  user: VATUser | null;
  /** Always null after the C11 phase 2 migration. The browser session
   * lives in the httpOnly vat-session cookie, not in JS-readable state.
   * Kept on the type for back-compat with any caller that still reads
   * it (callers should migrate to relying on the cookie). */
  token: string | null;
  setUser: (user: VATUser | null, token?: string | null) => void;
  userEmail: string | null;
  isAdmin: boolean | null;
  setIsAdmin: (v: boolean | null) => void;
  /** True once we've attempted to bootstrap session via /api/auth/me. */
  initialized: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUserState] = useState<VATUser | null>(null);
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    let cancelled = false;
    // One-shot purge of the legacy JWT-in-localStorage path. Old
    // sessions that used to depend on vat-token are gone after this
    // bootstrap; they'll either be picked up by the cookie path
    // (fetchMe succeeds) or the user gets redirected to /login.
    try {
      localStorage.removeItem(LEGACY_TOKEN_KEY);
    } catch {
      /* ignore */
    }
    (async () => {
      const me = await fetchMe();
      if (cancelled) return;
      if (me?.id && me?.email) {
        const u: VATUser = {
          id: me.id,
          email: me.email,
          role: me.role,
          tenant_id: me.tenant_id,
        };
        setUserState(u);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
        } catch {
          /* ignore quota errors */
        }
      } else {
        // Cookie missed — clear any stale cached profile so AuthGuard
        // sees a clean unauthenticated state.
        try {
          localStorage.removeItem(STORAGE_KEY);
        } catch {
          /* ignore */
        }
      }
      setInitialized(true);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    setOnUnauthorized(() => {
      setUserState(null);
      if (typeof window !== "undefined") {
        try {
          localStorage.removeItem(STORAGE_KEY);
          localStorage.removeItem(LEGACY_TOKEN_KEY);
        } catch {
          /* ignore */
        }
      }
      void logoutSession();
    });
    return () => setOnUnauthorized(null);
  }, []);

  const setUser = useCallback((u: VATUser | null, _token?: string | null) => {
    if (u === null) {
      setUserState(null);
      if (typeof window !== "undefined") {
        try {
          localStorage.removeItem(STORAGE_KEY);
          localStorage.removeItem(LEGACY_TOKEN_KEY);
        } catch {
          /* ignore */
        }
      }
      void logoutSession();
    } else {
      setUserState(u);
      // The token argument is ignored — the cookie carries the session.
      // Keeping the parameter on the signature for back-compat with
      // callers that still pass it (login form, OAuth code exchange).
      if (typeof window !== "undefined") {
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
          localStorage.removeItem(LEGACY_TOKEN_KEY);
        } catch {
          /* ignore */
        }
      }
    }
    setIsAdmin(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token: null,
        setUser,
        userEmail: user?.email ?? null,
        isAdmin,
        setIsAdmin,
        initialized,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
