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

const STORAGE_KEY = "vat-user";
// Legacy: pre-cookie sessions stored the JWT here. We no longer write
// to it; the entry is purged on first load below. The cookie path is
// the only credential surface for new sessions.
const LEGACY_TOKEN_KEY = "vat-token";

export interface VATUser {
  id: string;
  email: string;
  role: string;
  tenant_id: string | null;
}

interface AuthContextValue {
  user: VATUser | null;
  /** Legacy in-memory token, present only for sessions migrated from the
   * old localStorage path. New cookie sessions return null here. The API
   * client falls back to the cookie automatically when token is null. */
  token: string | null;
  setUser: (user: VATUser | null, token?: string | null) => void;
  userEmail: string | null;
  isAdmin: boolean | null;
  setIsAdmin: (v: boolean | null) => void;
  /** True once we've attempted to restore session (cookie + localStorage
   * fallback). Don't redirect before this. */
  initialized: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUserState] = useState<VATUser | null>(null);
  const [token, setTokenState] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    let cancelled = false;
    (async () => {
      // 1. Prefer the cookie session — fetchMe sends the httpOnly
      //    vat-session cookie via credentials: "include". This is the
      //    authoritative path for new sessions; the JWT is never read
      //    into JS and so cannot be exfiltrated by a DOM XSS sink.
      const me = await fetchMe();
      if (cancelled) return;
      if (me?.id && me?.email) {
        setUserState({
          id: me.id,
          email: me.email,
          role: me.role,
          tenant_id: me.tenant_id,
        });
        setTokenState(null);
        // Clear legacy token from any pre-migration session — server
        // accepts cookie now, so this entry is no longer needed.
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(me));
          localStorage.removeItem(LEGACY_TOKEN_KEY);
        } catch {
          /* ignore quota / storage-disabled errors */
        }
        setInitialized(true);
        return;
      }

      // 2. Cookie miss — fall back to the legacy localStorage path so
      //    sessions issued before this change still resolve. Once the
      //    next API call refreshes auth via the cookie path, this
      //    fallback becomes inert.
      const storedUser = localStorage.getItem(STORAGE_KEY);
      const storedToken = localStorage.getItem(LEGACY_TOKEN_KEY);
      if (storedUser && storedToken) {
        try {
          const parsed = JSON.parse(storedUser) as VATUser;
          if (parsed?.id && parsed?.email) {
            setUserState(parsed);
            setTokenState(storedToken);
          }
        } catch {
          localStorage.removeItem(STORAGE_KEY);
          localStorage.removeItem(LEGACY_TOKEN_KEY);
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
      setTokenState(null);
      if (typeof window !== "undefined") {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(LEGACY_TOKEN_KEY);
      }
      // Best-effort cookie clear so the browser doesn't keep sending a
      // server-rejected cookie. Fire-and-forget; AuthGuard will redirect
      // regardless of the response.
      void logoutSession();
    });
    return () => setOnUnauthorized(null);
  }, []);

  const setUser = useCallback((u: VATUser | null, t?: string | null) => {
    if (u === null) {
      setUserState(null);
      setTokenState(null);
      if (typeof window !== "undefined") {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(LEGACY_TOKEN_KEY);
      }
      void logoutSession();
    } else {
      setUserState(u);
      // Token from the login/exchange-code response is held in memory
      // only — NOT written to localStorage anymore. The httpOnly cookie
      // already persists the session across reloads.
      const tok = t !== undefined ? t : null;
      setTokenState(tok);
      if (typeof window !== "undefined") {
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
          // Defensive: purge any stale legacy token left over from a
          // prior session that predates this change.
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
        token,
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
