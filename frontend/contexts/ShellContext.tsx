"use client";

import { createContext, useContext } from "react";

interface ShellContextValue {
  /** When true, the main header and footer are rendered by a parent (MainAppShell). */
  embedded: boolean;
}

const ShellContext = createContext<ShellContextValue>({ embedded: false });

export function ShellProvider({
  embedded,
  children,
}: {
  embedded: boolean;
  children: React.ReactNode;
}) {
  return (
    <ShellContext.Provider value={{ embedded }}>{children}</ShellContext.Provider>
  );
}

export function useShellContext() {
  return useContext(ShellContext);
}
