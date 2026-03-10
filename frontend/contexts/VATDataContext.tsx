"use client";

import { createContext, useContext } from "react";
import type { UseVATDataReturn } from "@/hooks/useVATData";
import { useVATDataCore } from "@/hooks/useVATData";

const VATDataContext = createContext<UseVATDataReturn | null>(null);

export function VATDataProvider({ children }: { children: React.ReactNode }) {
  const data = useVATDataCore();
  return (
    <VATDataContext.Provider value={data}>{children}</VATDataContext.Provider>
  );
}

export function useVATData(): UseVATDataReturn {
  const ctx = useContext(VATDataContext);
  if (!ctx) {
    throw new Error("useVATData must be used within VATDataProvider");
  }
  return ctx;
}
