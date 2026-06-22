"use client";

import React, {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
  type InputHTMLAttributes,
} from "react";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";

export const DEFAULT_SEARCH_DEBOUNCE_MS = 300;

type SearchInputProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "onChange" | "type" | "value"
> & {
  value: string;
  onValueChange: (value: string) => void;
  debounceMs?: number;
  normalizeValue?: (value: string) => string;
};

const identity = (value: string) => value;

export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(
  function SearchInput(
    {
      debounceMs = DEFAULT_SEARCH_DEBOUNCE_MS,
      normalizeValue = identity,
      onValueChange,
      value,
      ...props
    },
    forwardedRef,
  ) {
    const inputRef = useRef<HTMLInputElement>(null);
    const lastEmittedValue = useRef(value);
    const hasUserEdited = useRef(false);
    const [draftValue, setDraftValue] = useState(value);
    const debouncedDraftValue = useDebouncedValue(draftValue, debounceMs);

    useImperativeHandle(forwardedRef, () => inputRef.current as HTMLInputElement);

    useEffect(() => {
      lastEmittedValue.current = value;
      setDraftValue(value);
    }, [value]);

    useEffect(() => {
      if (!hasUserEdited.current) return;
      const nextValue = normalizeValue(debouncedDraftValue);
      if (nextValue === lastEmittedValue.current) return;

      lastEmittedValue.current = nextValue;
      onValueChange(nextValue);
    }, [debouncedDraftValue, normalizeValue, onValueChange]);

    const handleChange = useCallback(
      (event: React.ChangeEvent<HTMLInputElement>) => {
        hasUserEdited.current = true;
        setDraftValue(event.target.value);
      },
      [],
    );

    return (
      <input
        {...props}
        ref={inputRef}
        type="search"
        value={draftValue}
        onChange={handleChange}
      />
    );
  },
);
