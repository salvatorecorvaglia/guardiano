import type { ReactNode } from "react";
import { ErrorBox, Spinner } from "./ui";

type QueryState = {
  isPending: boolean;
  error: unknown;
  refetch: () => Promise<unknown>;
};

/** Keep a panel's loading, failure and retry behavior consistent across dependent queries. */
export default function AsyncState({ queries, label = "Content", children }: {
  queries: readonly QueryState[]; label?: string; children: ReactNode;
}) {
  const failed = queries.filter((query) => query.error != null);
  if (failed.length) return (
    <div className="space-y-2">
      <ErrorBox error={failed[0].error} />
      <button className="btn-secondary" onClick={() => { for (const query of failed) void query.refetch(); }}>
        Retry {label.toLowerCase()}
      </button>
    </div>
  );
  if (queries.some((query) => query.isPending)) return <div role="status" aria-label={`Loading ${label.toLowerCase()}`} className="flex justify-center py-6"><Spinner /></div>;
  return <>{children}</>;
}
