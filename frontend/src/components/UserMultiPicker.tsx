import { useUserNames } from "../api/queries";
import { ErrorBox } from "./ui";
import AsyncPicker from "./AsyncPicker";

/** Selected identities stay visible as the bounded search results change. */
export default function UserMultiPicker({ label, value, onChange, disabled, maxSelected = 500 }: {
  label: string; value: number[]; onChange: (ids: number[]) => void; disabled?: boolean; maxSelected?: number;
}) {
  const names = useUserNames(value);
  return <div className="space-y-2">
    <AsyncPicker kind="users" label={`Add ${label.toLowerCase()}`} value="" emptyLabel="Select a person…" disabled={disabled || value.length >= maxSelected}
      onChange={(id) => { if (id && !value.includes(Number(id))) onChange([...value, Number(id)]); }} />
    {names.error && <div><ErrorBox error={names.error} /><button type="button" className="btn-ghost text-xs" onClick={() => void names.retry()}>Retry selected people</button></div>}
    <ul className="max-h-48 space-y-1 overflow-y-auto">
      {value.map((id) => {
        const person = names.data.find((item) => item.id === id);
        const name = person ? person.full_name || person.email : `User #${id}`;
        return <li key={id} className="flex items-center justify-between gap-2 text-sm">
          <span>{name}</span><button type="button" className="btn-ghost text-xs" disabled={disabled} aria-label={`Remove ${name}`}
            onClick={() => onChange(value.filter((item) => item !== id))}>Remove</button>
        </li>;
      })}
    </ul>
  </div>;
}
