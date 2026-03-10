"use client";

import { useState, useEffect } from "react";

/**
 * Returns a debounced version of the value that updates only after the
 * specified delay has passed without new changes.
 * Useful for search inputs to avoid triggering API calls or filters on every keystroke.
 */
export function useDebouncedValue<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debouncedValue;
}
