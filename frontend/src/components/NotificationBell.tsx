import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Bell } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { request } from "../api/typed";

import { relTime } from "../lib/format";

const KEY = ["notifications"];

/** The bell: assignments, mentions, approvals and deadlines that concern you (services/notifications.py). */
export default function NotificationBell() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const list = useQuery({
    queryKey: KEY,
    queryFn: ({ signal }) => request("get", "/api/v1/notifications", { signal }),
    refetchInterval: 60_000,
  });
  const read = useMutation({
    mutationFn: (ids: number[] | null) => request("post", "/api/v1/notifications/read", { body: { ids } }),
    onSuccess: (data) => qc.setQueryData(KEY, data),
  });

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !box.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  const unread = list.data?.unread ?? 0;
  const items = list.data?.items ?? [];
  return (
    <div className="relative" ref={box}>
      <button
        className="btn-ghost relative p-1.5"
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <Bell className="h-5 w-5" />
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 min-w-[1.1rem] rounded-full bg-danger px-1 text-center text-[10px] font-semibold leading-[1.1rem] text-white">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-lg border border-line bg-raised shadow-lg">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="text-sm font-semibold">Notifications</span>
            {unread > 0 && (
              <button className="text-xs text-accent hover:underline" onClick={() => read.mutate(null)}>
                Mark all read
              </button>
            )}
          </div>
          <ul className="max-h-96 divide-y divide-line overflow-y-auto">
            {items.map((n) => (
              <li key={n.id}>
                <button
                  className={clsx("block w-full px-3 py-2 text-left text-sm hover:bg-ink/[0.03]", !n.read_at && "bg-accent/5")}
                  onClick={() => {
                    if (!n.read_at) read.mutate([n.id]);
                    setOpen(false);
                    if (n.finding_id) navigate(`/findings/${n.finding_id}`);
                  }}
                >
                  <span className={clsx("line-clamp-2", !n.read_at && "font-medium")}>{n.text}</span>
                  <span className="text-xs text-muted">{relTime(n.created_at)}</span>
                </button>
              </li>
            ))}
            {items.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted">Nothing new</li>}
          </ul>
        </div>
      )}
    </div>
  );
}
