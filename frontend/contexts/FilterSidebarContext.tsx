"use client";

import { createContext, useContext } from "react";

interface FilterSidebarContextValue {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FilterSidebarContext = createContext<FilterSidebarContextValue | null>(
  null,
);

export function FilterSidebarProvider({
  open,
  onOpenChange,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <FilterSidebarContext.Provider value={{ open, onOpenChange }}>
      {children}
    </FilterSidebarContext.Provider>
  );
}

export function useFilterSidebar() {
  const ctx = useContext(FilterSidebarContext);
  return ctx ?? { open: false, onOpenChange: () => {} };
}
