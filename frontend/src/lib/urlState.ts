import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

export type ParamChanges = Record<string, string | string[] | null>;

/** URL-backed page state. Updates are functional, so they never overwrite a concurrent change. */
export function useUrlParams() {
  const [params, setParams] = useSearchParams();
  const update = useCallback(
    (changes: ParamChanges, keepPage = false) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(changes)) {
            next.delete(k);
            if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
            else if (v) next.set(k, v);
          }
          if (!keepPage) next.delete("page");
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  const rawPage = Number(params.get("page"));
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 ? rawPage : 1;
  return { params, update, page };
}

/**
 * A text input bound to one URL param: typing is debounced into the URL, and the input follows the
 * URL when it changes elsewhere (navigation, back/forward, "clear filters").
 */
export function useDebouncedParam(
  key: string,
  params: URLSearchParams,
  update: (c: ParamChanges) => void,
  delay = 350,
): [string, (v: string) => void] {
  const urlValue = params.get(key) ?? "";
  const [value, setValue] = useState(urlValue);
  useEffect(() => setValue(urlValue), [urlValue]);
  useEffect(() => {
    if (value === urlValue) return;
    const t = setTimeout(() => update({ [key]: value || null }), delay);
    return () => clearTimeout(t);
  }, [value, urlValue, key, update, delay]);
  return [value, setValue];
}

/** When the current page is past the end (e.g. after a bulk update shrank the results), jump to the last one. */
export function useClampPage(page: number, pageSize: number, total: number | undefined, update: (c: ParamChanges, keepPage?: boolean) => void, placeholder = false) {
  useEffect(() => {
    if (total === undefined || placeholder) return;
    const last = Math.max(1, Math.ceil(total / pageSize));
    if (page > last) update({ page: last > 1 ? String(last) : null }, true);
  }, [page, pageSize, total, update, placeholder]);
}

/** A query string reduced to what identifies a result set: no paging, no sort, pairs in a stable order. */
export function canonicalQuery(search: string): string {
  const pairs = [...new URLSearchParams(search.replace(/^\?/, "")).entries()].filter(([k, v]) => v && k !== "page" && k !== "sort");
  pairs.sort(([ak, av], [bk, bv]) => (ak === bk ? av.localeCompare(bv) : ak.localeCompare(bk)));
  return new URLSearchParams(pairs).toString();
}


/** Calendar dates in shared URLs must round-trip; Date otherwise rolls invalid days forward. */
export function validCalendarDate(value: string | null | undefined): boolean {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split("-").map(Number);
  if (year < 100) return false;
  const date = new Date(0);
  date.setFullYear(year, month - 1, day);
  return date.getFullYear() === year && date.getMonth() === month - 1 && date.getDate() === day;
}

/** Empty filter values mean no numeric filter; preserve invalid input as NaN for API validation. */
export function optionalNumber(value: string | null | undefined): number | undefined {
  return value == null || value === "" ? undefined : Number(value);
}
