import { CheckCircle2, X } from "lucide-react";
import { createContext, type ReactNode, useCallback, useContext, useMemo, useRef, useState } from "react";

interface Toast {
  id: number;
  message: string;
}

const ToastContext = createContext<(message: string) => void>(() => {});

/** Transient success feedback for mutations (errors stay inline next to the control that failed). */
export function Toaster({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (message: string) => {
      const id = nextId.current++;
      setToasts((t) => [...t.slice(-2), { id, message }]);
      setTimeout(() => dismiss(id), 4000);
    },
    [dismiss],
  );
  const value = useMemo(() => toast, [toast]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex flex-col gap-2" aria-live="polite" role="status">
        {toasts.map((t) => (
          <div key={t.id} className="card pointer-events-auto flex items-center gap-2 bg-raised px-3 py-2 text-sm shadow-lg">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-good" aria-hidden />
            <span>{t.message}</span>
            <button className="btn-ghost -mr-1 p-0.5" onClick={() => dismiss(t.id)} aria-label="Dismiss">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// biome-ignore lint/style/useComponentExportOnlyModules: This hook intentionally shares its provider module.
export const useToast = () => useContext(ToastContext);
