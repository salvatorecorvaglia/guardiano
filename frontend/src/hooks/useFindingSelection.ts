import { type SetStateAction, useCallback, useState } from "react";

const EMPTY = new Set<number>();

/** A selection belongs to exactly one result query; a changed URL invalidates it synchronously. */
export function useFindingSelection(queryKey: string) {
  const [state, setState] = useState({
    key: queryKey,
    ids: EMPTY,
    matching: false,
  });
  if (state.key !== queryKey)
    setState({ key: queryKey, ids: EMPTY, matching: false });
  const selected = state.key === queryKey ? state.ids : EMPTY;
  const allMatching = state.key === queryKey && state.matching;
  const setSelected = useCallback(
    (update: SetStateAction<Set<number>>) => {
      setState((previous) => {
        const current =
          previous.key === queryKey
            ? previous
            : { key: queryKey, ids: EMPTY, matching: false };
        return {
          ...current,
          ids: typeof update === "function" ? update(current.ids) : update,
        };
      });
    },
    [queryKey],
  );
  const setAllMatching = useCallback(
    (matching: boolean) => {
      setState((previous) => ({
        key: queryKey,
        ids: previous.key === queryKey ? previous.ids : EMPTY,
        matching,
      }));
    },
    [queryKey],
  );
  const toggleOne = useCallback(
    (id: number) => {
      setState((previous) => {
        const ids = new Set(previous.key === queryKey ? previous.ids : EMPTY);
        if (ids.has(id)) ids.delete(id);
        else ids.add(id);
        return { key: queryKey, ids, matching: false };
      });
    },
    [queryKey],
  );
  return { selected, allMatching, setSelected, setAllMatching, toggleOne };
}
