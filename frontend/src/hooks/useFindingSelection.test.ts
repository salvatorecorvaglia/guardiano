import { act, renderHook } from "@testing-library/react";
import { expect, it } from "vitest";
import { useFindingSelection } from "./useFindingSelection";

it("discards selection on a changed query and does not resurrect it on return", () => {
  const { result, rerender } = renderHook(
    ({ query }) => useFindingSelection(query),
    { initialProps: { query: "?severity=high" } },
  );
  act(() => result.current.toggleOne(42));
  act(() => result.current.setAllMatching(true));
  expect([...result.current.selected]).toEqual([42]);
  rerender({ query: "?severity=low" });
  expect(result.current.selected.size).toBe(0);
  expect(result.current.allMatching).toBe(false);
  rerender({ query: "?severity=high" });
  expect(result.current.selected.size).toBe(0);
  expect(result.current.allMatching).toBe(false);
});
