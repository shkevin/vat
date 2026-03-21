"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import {
  loadUserPreferences,
  saveUserPreferences,
  type ThemeId,
} from "@/lib/userPreferencesStorage";

interface ThemeContextValue {
  themeId: ThemeId;
  setThemeId: (id: ThemeId) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [themeId, setThemeIdState] = useState<ThemeId>("default");

  useEffect(() => {
    const prefs = loadUserPreferences();
    if (prefs.themeId) {
      setThemeIdState(prefs.themeId);
      if (typeof document !== "undefined") {
        document.documentElement.setAttribute("data-theme", prefs.themeId);
      }
    }
  }, []);

  useEffect(() => {
    if (typeof document === "undefined") return;
    document.documentElement.setAttribute("data-theme", themeId);
  }, [themeId]);

  const setThemeId = useCallback((id: ThemeId) => {
    setThemeIdState(id);
    saveUserPreferences({ themeId: id });
  }, []);

  return (
    <ThemeContext.Provider value={{ themeId, setThemeId }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
