// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import React, { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SearchInput } from "./SearchInput";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

describe("SearchInput", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps typing local and emits the search value only after the debounce delay", () => {
    const onValueChange = vi.fn();
    render(
      <SearchInput
        aria-label="Search assets"
        debounceMs={300}
        onValueChange={onValueChange}
        placeholder="Search assets"
        value=""
      />,
    );

    const input = screen.getByLabelText("Search assets") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "c" } });
    fireEvent.change(input, { target: { value: "cv" } });
    fireEvent.change(input, { target: { value: "cve" } });

    expect(input.value).toBe("cve");
    expect(onValueChange).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(299);
    });
    expect(onValueChange).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(onValueChange).toHaveBeenCalledTimes(1);
    expect(onValueChange).toHaveBeenCalledWith("cve");
  });
});
