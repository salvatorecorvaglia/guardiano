import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { type FormEvent, useId, useState } from "react";
import { Link } from "react-router-dom";
import { request } from "../api/typed";


// Mirrors FindingTag in app/schemas/finding.py.
const TAG_RE = /^[\w.:/+-]{1,64}$/;

/** Finding tags as links to the filtered list; editable when `onChange` is given. */
export default function TagEditor({ tags, onChange, pending }: { tags: string[]; onChange?: (tags: string[]) => void; pending?: boolean }) {
  const [draft, setDraft] = useState("");
  const listId = useId();
  const suggestions = useQuery({
    queryKey: ["finding-tags"],
    queryFn: ({ signal }) => request("get", "/api/v1/findings/tags", { signal, query: { limit: 100 } }),
    enabled: !!onChange,
    staleTime: 60_000,
  });
  const value = draft.trim().toLowerCase();
  const valid = TAG_RE.test(value) && !tags.includes(value);

  function add(e: FormEvent) {
    e.preventDefault();
    if (valid && onChange) {
      onChange([...tags, value]);
      setDraft("");
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {tags.map((t) => (
        <span key={t} className="inline-flex items-center gap-1 rounded bg-ink/5 px-1.5 py-0.5 text-xs">
          <Link to={`/findings?tag=${encodeURIComponent(t)}`} className="hover:text-accent">
            {t}
          </Link>
          {onChange && (
            <button className="text-muted hover:text-danger" aria-label={`Remove tag ${t}`} disabled={pending} onClick={() => onChange(tags.filter((x) => x !== t))}>
              <X className="h-3 w-3" />
            </button>
          )}
        </span>
      ))}
      {!tags.length && !onChange && <span className="text-muted">–</span>}
      {onChange && (
        <form onSubmit={add}>
          <input
            className="input w-32 px-2 py-0.5 text-xs"
            placeholder="Add tag…"
            aria-label="Add tag"
            aria-invalid={!!value && !TAG_RE.test(value)}
            list={listId}
            maxLength={64}
            value={draft}
            disabled={pending}
            onChange={(e) => setDraft(e.target.value)}
          />
          <datalist id={listId}>
            {suggestions.data
              ?.filter((s) => !tags.includes(s.tag))
              .map((s) => (
                <option key={s.tag} value={s.tag} />
              ))}
          </datalist>
        </form>
      )}
    </div>
  );
}
