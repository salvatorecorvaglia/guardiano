import { useQuery } from "@tanstack/react-query";
import { type ReactNode, useEffect, useState } from "react";
import { request } from "../api/typed";
import { ErrorBox } from "./ui";

export type PickerOption = { id: number; name: string };

/** Native keyboard selection with bounded, cancellable search and explicit result pages. */
export default function AsyncPicker({ kind, label, value, onChange, emptyLabel, extraOptions = [], disabled,
  selectedOption, emptyDisabled, className = "", }: {
  kind: "assets" | "users"; label: string; value: string; onChange: (value: string) => void;
  emptyLabel: string; extraOptions?: { value: string; label: string }[]; disabled?: boolean;
  emptyDisabled?: boolean; selectedOption?: PickerOption; className?: string;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState({ q: "", page: 1 });
  useEffect(() => {
    const timeout = setTimeout(() => setFilter((state) => state.q === search ? state : { q: search, page: 1 }), 200);
    return () => clearTimeout(timeout);
  }, [search]);
  const selectedId = /^\d+$/.test(value) ? Number(value) : undefined;
  const query = useQuery({
    queryKey: [kind, "picker", filter.q, filter.page, selectedId],
    queryFn: async ({ signal }) => {
      const params = { ...filter, selected_id: selectedId, page_size: 50 };
      if (kind === "assets") return request("get", "/api/v1/assets/options/search", { query: params, signal });
      const page = await request("get", "/api/v1/users/directory/search", { query: params, signal });
      const option = (user: { id: number; full_name: string; email: string }) => ({ id: user.id, name: user.full_name || user.email });
      return { ...page, items: page.items.map(option), selected: page.selected ? option(page.selected) : null };
    },
  });
  useEffect(() => {
    if (query.data && filter.page > Math.max(1, Math.ceil(query.data.total / 50))) {
      setFilter((state) => ({ ...state, page: Math.max(1, Math.ceil(query.data!.total / 50)) }));
    }
  }, [query.data, filter.page]);
  const items = query.data?.items ?? [];
  const selected = query.data?.selected ?? (selectedOption?.id === selectedId ? selectedOption : null);
  const special = new Set(extraOptions.map((option) => option.value));
  const options: ReactNode[] = extraOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>);
  if (selected && !special.has(String(selected.id)) && !items.some((item) => item.id === selected.id)) {
    options.push(<option key={selected.id} value={selected.id}>{selected.name}</option>);
  }
  if (value && !selected && !special.has(value) && !items.some((item) => String(item.id) === value)) {
    options.push(<option key="unavailable" value={value} disabled>Unavailable selection</option>);
  }
  for (const item of items) if (!special.has(String(item.id))) options.push(<option key={item.id} value={item.id}>{item.name}</option>);
  return (
    <div className={`min-w-36 max-w-xs space-y-1 ${className}`}>
      <input className="input py-1 text-xs" type="search" maxLength={200} aria-label={`Search ${label.toLowerCase()}`}
        placeholder={`Search ${kind}…`} value={search} disabled={disabled} onChange={(event) => setSearch(event.target.value)} />
      <select className="input w-full" aria-label={label} value={value} disabled={disabled || query.isFetching || query.isError || search !== filter.q || !query.data}
        onChange={(event) => onChange(event.target.value)}>
        <option value="" disabled={emptyDisabled}>{emptyLabel}</option>{options}
      </select>
      {query.data && !query.isFetching && !query.isError && items.length === 0 && <p className="text-xs text-muted">No matching {kind}.</p>}
      {query.isFetching && <p className="text-xs text-muted" role="status">Loading options…</p>}
      {query.isError && <div><ErrorBox error={query.error} /><button type="button" className="btn-ghost text-xs" onClick={() => void query.refetch()}>Retry {label.toLowerCase()}</button></div>}
      {query.data && query.data.total > 50 && <div className="flex items-center justify-between gap-2 text-xs text-muted">
        <button type="button" className="btn-ghost" aria-label={`Previous ${label.toLowerCase()} results`} disabled={filter.page === 1 || query.isFetching}
          onClick={() => setFilter((state) => ({ ...state, page: state.page - 1 }))}>Previous</button>
        <span>{filter.page} / {Math.ceil(query.data.total / 50)}</span>
        <button type="button" className="btn-ghost" aria-label={`Next ${label.toLowerCase()} results`} disabled={filter.page * 50 >= query.data.total || query.isFetching}
          onClick={() => setFilter((state) => ({ ...state, page: state.page + 1 }))}>Next</button>
      </div>}
    </div>
  );
}
