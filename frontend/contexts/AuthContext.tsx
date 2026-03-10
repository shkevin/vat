"use client";

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { setOnUnauthorized } from "@/lib/onUnauthorized";

const STORAGE_KEY = "vat-user";
const STORAGE_KEY_TOKEN = "vat-token";

export interface VATUser {
  id: string;
  email: string;
  role: string;
  tenant_id: string | null;
}

interface AuthContextValue {
  user: VATUser | null;
  token: string | null;
  setUser: (user: VATUser | null, token?: string | null) => void;
  userEmail: string | null;
  isAdmin: boolean | null;
  setIsAdmin: (v: boolean | null) => void;
  /** True once we've restored session from localStorage. Don't redirect before this. */
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
    const storedUser = localStorage.getItem(STORAGE_KEY);
    const storedToken = localStorage.getItem(STORAGE_KEY_TOKEN);
    if (storedUser) {
      try {
        const parsed = JSON.parse(storedUser) as VATUser;
        if (parsed?.id && parsed?.email) {
          setUserState(parsed);
          if (storedToken) setTokenState(storedToken);
        }
      } catch {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(STORAGE_KEY_TOKEN);
      }
    }
    setInitialized(true);
  }, []);

  useEffect(() => {
    setOnUnauthorized(() => {
      setUserState(null);
      setTokenState(null);
      if (typeof window !== "undefined") {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(STORAGE_KEY_TOKEN);
      }
    });
    return () => setOnUnauthorized(null);
  }, []);

  const setUser = useCallback((u: VATUser | null, t?: string | null) => {
    if (u === null) {
      setUserState(null);
      setTokenState(null);
      if (typeof window !== "undefined") {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(STORAGE_KEY_TOKEN);
      }
    } else {
      setUserState(u);
      const tok = t !== undefined ? t : (typeof window !== "undefined" ? localStorage.getItem(STORAGE_KEY_TOKEN) : null);
      setTokenState(tok);
      if (typeof window !== "undefined") {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
        if (tok) localStorage.setItem(STORAGE_KEY_TOKEN, tok);
        else localStorage.removeItem(STORAGE_KEY_TOKEN);
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
