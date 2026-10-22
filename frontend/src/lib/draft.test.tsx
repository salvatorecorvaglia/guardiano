import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { canonical, useServerDraft } from "./draft";

describe("canonical", () => {
  it("ignores key order and cleared fields", () => {
    expect(canonical({ a: 1, b: { y: "2", x: "" } })).toBe(canonical({ b: { y: "2" }, a: 1 }));
    expect(canonical({ critical: "" })).toBe(canonical({}));
  });

  it("still tells real differences apart", () => {
    expect(canonical({ critical: "5" })).not.toBe(canonical({}));
    expect(canonical([1, 2])).not.toBe(canonical([2, 1]));
  });
});

describe("useServerDraft", () => {
  it("follows the server until edited, then keeps the edits through a refetch", () => {
    const { result, rerender } = renderHook(({ server }) => useServerDraft(server), {
      initialProps: { server: { days: "7" } },
    });
    expect(result.current.value).toEqual({ days: "7" });

    act(() => result.current.set({ days: "14" }));
    expect(result.current.dirty).toBe(true);

    rerender({ server: { days: "7" } }); // a background refetch with the same data, as a new object
    expect(result.current.value).toEqual({ days: "14" });
  });

  it("is not dirty after typing a value and clearing it again", () => {
    const { result } = renderHook(() => useServerDraft<Record<string, string>>({}));
    act(() => result.current.set({ critical: "5" }));
    act(() => result.current.set({ critical: "" }));
    expect(result.current.dirty).toBe(false);
  });

  it("hands the form back to the server on discard", () => {
    const { result, rerender } = renderHook(({ server }) => useServerDraft(server), {
      initialProps: { server: { days: "7" } },
    });
    act(() => result.current.set({ days: "14" }));
    act(() => result.current.discard());
    rerender({ server: { days: "30" } });
    expect(result.current.value).toEqual({ days: "30" });
    expect(result.current.dirty).toBe(false);
  });
});
