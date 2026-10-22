import { useCallback, useState } from "react";

/**
 * The same value written in a canonical form: object keys sorted, and empty strings dropped, because
 * a cleared input ("") and a key that was never there mean the same thing to every form using this.
 * JSON.stringify of the raw objects did not: typing into a field and clearing it again left the form
 * "changed" forever, and so did the same keys arriving in a different order from the server.
 */
export function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>)
          .filter(([, x]) => x !== "")
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
      );
    }
    return v;
  });
}

/**
 * A form's editable copy of server state.
 *
 * Until somebody edits, the form shows the server's value and follows it as it refetches. From the
 * first edit it shows theirs, and a refetch -- another card's save invalidating the query, a window
 * refocus -- can no longer overwrite what they typed. `discard` (and a successful save) hands the form
 * back to the server. The cards that used this pattern reseeded from the server in an effect on every
 * refetch instead, which silently threw unsaved edits away.
 */
export function useServerDraft<D>(server: D | undefined) {
  const [edits, setEdits] = useState<D | null>(null);
  const value = edits ?? server;
  const dirty = edits !== null && server !== undefined && canonical(edits) !== canonical(server);
  const discard = useCallback(() => setEdits(null), []);
  return { value, set: setEdits as (d: D) => void, dirty, discard };
}
