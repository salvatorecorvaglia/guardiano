import { OPTIONAL_COLUMNS, type OptionalColumn } from "./columns";

export function ColumnChooser({ hidden, onChange }: { hidden: ReadonlySet<OptionalColumn>; onChange: (h: ReadonlySet<OptionalColumn>) => void }) {
  return (
    <details className="relative">
      <summary className="btn-secondary cursor-pointer list-none">Columns</summary>
      <div className="absolute right-0 z-20 mt-1 w-44 space-y-1 rounded-lg border border-line bg-raised p-2 shadow-lg">
        {OPTIONAL_COLUMNS.map((c) => (
          <label key={c.key} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={!hidden.has(c.key)}
              onChange={() => {
                const next = new Set(hidden);
                if (next.has(c.key)) next.delete(c.key);
                else next.add(c.key);
                onChange(next);
              }}
            />
            {c.label}
          </label>
        ))}
      </div>
    </details>
  );
}

