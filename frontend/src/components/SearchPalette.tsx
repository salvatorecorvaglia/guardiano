import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { request } from "../api/typed";

import { findingLocation } from "../lib/format";
import { ErrorBox, Modal, Spinner } from "./ui";

type Hit = { key: string; group: string; label: string; sub?: string; to: string };

function typing(target: EventTarget | null) {
  const el = target as HTMLElement | null;
  return !!el && (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));
}

/** Ctrl/Cmd-K (or "/") from anywhere: findings, assets, packages and vulnerabilities in one box. */
export default function SearchPalette() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "/" && !typing(e.target)) {
        e.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => {
    if (open) setTimeout(() => input.current?.focus(), 0);
    else {
      setText("");
      setQ("");
    }
  }, [open]);
  useEffect(() => {
    const t = setTimeout(() => setQ(text.trim()), 200);
    return () => clearTimeout(t);
  }, [text]);

  const result = useQuery({
    queryKey: ["search", q],
    queryFn: ({ signal }) => request("get", "/api/v1/search", { signal, query: { q } }),
    enabled: open && q.length >= 2,
  });
  const hits = useMemo<Hit[]>(() => {
    const r = result.data;
    if (!r) return [];
    return [
      ...(r.vulnerability ? [{ key: `v-${r.vulnerability}`, group: "Vulnerability", label: r.vulnerability, sub: "Across every asset", to: `/vulnerabilities/${r.vulnerability}` }] : []),
      ...r.findings.map((f) => ({ key: `f-${f.id}`, group: "Findings", label: f.title, sub: `${f.asset.name} · ${findingLocation(f)}`, to: `/findings/${f.id}` })),
      ...r.assets.map((a) => ({ key: `a-${a.id}`, group: "Assets", label: a.name, to: `/assets/${a.id}` })),
      ...r.packages.map((p) => ({
        key: `p-${p.ecosystem}-${p.name}`,
        group: "Packages",
        label: p.name,
        sub: `${p.ecosystem ?? "?"} · ${p.assets} asset${p.assets === 1 ? "" : "s"}`,
        to: `/components?q=${encodeURIComponent(p.name)}`,
      })),
    ];
  }, [result.data]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: A new result list resets keyboard selection.
  useEffect(() => setActive(0), [hits]);

  function go(hit: Hit | undefined) {
    if (!hit) return;
    setOpen(false);
    navigate(hit.to);
  }

  return (
    <>
      <button className="btn-ghost hidden items-center gap-2 text-sm text-muted sm:inline-flex" onClick={() => setOpen(true)} aria-label="Search">
        <Search className="h-4 w-4" /> Search… <kbd className="rounded border border-line px-1 font-mono text-[10px]">⌘K</kbd>
      </button>
      <button className="btn-ghost p-1.5 sm:hidden" onClick={() => setOpen(true)} aria-label="Search">
        <Search className="h-5 w-5" />
      </button>
      {open && (
        <Modal open onClose={() => setOpen(false)} title="Search" wide>
          <div
            className="w-full overflow-hidden"
          >
            <div className="flex items-center gap-2 border-b border-line px-3">
              <Search className="h-4 w-4 text-muted" />
              <input
                ref={input}
                className="w-full bg-transparent py-3 text-sm outline-none"
                placeholder="Findings, assets, packages, CVE-…"
                aria-label="Search query"
                role="combobox"
                aria-expanded={hits.length > 0}
                aria-controls="search-results"
                aria-activedescendant={hits[active] ? `search-option-${active}` : undefined}
                value={text}
                onChange={(e) => setText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") setOpen(false);
                  else if (e.key === "ArrowDown") {
                    e.preventDefault();
                    setActive((i) => Math.max(0, Math.min(i + 1, hits.length - 1)));
                  } else if (e.key === "ArrowUp") {
                    e.preventDefault();
                    setActive((i) => Math.max(i - 1, 0));
                  } else if (e.key === "Enter") go(hits[active]);
                }}
              />
            </div>
            <ul id="search-results" role="listbox" className="max-h-[60vh] overflow-y-auto py-1">
              {hits.map((h, i) => (
                <li id={`search-option-${i}`} key={h.key} role="option" aria-selected={i === active}>
                  {(i === 0 || hits[i - 1].group !== h.group) && (
                    <div className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wide text-muted">{h.group}</div>
                  )}
                  <button
                    tabIndex={-1}
                    className={clsx("block w-full px-3 py-1.5 text-left text-sm", i === active && "bg-accent/10")}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => go(h)}
                  >
                    <span className="line-clamp-1 font-medium">{h.label}</span>
                    {h.sub && <span className="line-clamp-1 font-mono text-xs text-muted">{h.sub}</span>}
                  </button>
                </li>
              ))}
              {q.length >= 2 && result.isSuccess && hits.length === 0 && (
                <li className="px-3 py-6 text-center text-sm text-muted">Nothing matches “{q}”</li>
              )}
              {q.length < 2 && <li className="px-3 py-6 text-center text-sm text-muted">Type at least two characters</li>}
            </ul>
            {result.isFetching && <div role="status" className="flex items-center gap-2 p-3 text-sm text-muted"><Spinner />Searching…</div>}
            <ErrorBox error={result.error} />
          </div>
        </Modal>
      )}
    </>
  );
}
