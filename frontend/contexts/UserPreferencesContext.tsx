"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  loadUserPreferences,
  saveUserPreferences,
  type UserPreferences,
} from "@/lib/userPreferencesStorage";

const DEFAULT_PREFERENCES: UserPreferences = {
  tableDensity: "default",
  collapsedSections: [],
  themeId: "default",
  groupFindings: true,
};

const UserPreferencesContext = createContext<{
  preferences: UserPreferences;
  setPreferences: (updates: Partial<UserPreferences>) => void;
} | null>(null);

export function UserPreferencesProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [preferences, setPreferencesState] = useState<UserPreferences>(() =>
    typeof window !== "undefined" ? loadUserPreferences() : DEFAULT_PREFERENCES,
  );

  useEffect(() => {
    setPreferencesState(loadUserPreferences());
  }, []);

  const setPreferences = useCallback((updates: Partial<UserPreferences>) => {
    setPreferencesState((prev) => {
      const next = { ...prev, ...updates };
      saveUserPreferences(next);
      return next;
    });
  }, []);

  const value = useMemo(
    () => ({ preferences, setPreferences }),
    [preferences, setPreferences],
  );

  return (
    <UserPreferencesContext.Provider value={value}>
      {children}
    </UserPreferencesContext.Provider>
  );
}

export function useUserPreferences() {
  const ctx = useContext(UserPreferencesContext);
  if (!ctx)
    throw new Error(
      "useUserPreferences must be used within UserPreferencesProvider",
    );
  return ctx;
}
