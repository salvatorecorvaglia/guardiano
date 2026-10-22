import clsx from "clsx";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import type { GateResult } from "../api/types";

/** Pass/fail chip for a scan's quality gate. Renders nothing when no policy applied. */
export default function GateBadge({ gate, className }: { gate: GateResult | null | undefined; className?: string }) {
  if (!gate) return null;
  const Icon = gate.passed ? ShieldCheck : ShieldAlert;
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium",
        gate.passed ? "border-good/40 bg-good/10 text-good" : "border-danger/40 bg-danger/10 text-danger",
        className,
      )}
      title={gate.passed ? "Quality gate passed" : gate.violations.map((v) => v.message).join("\n")}
    >
      <Icon className="h-3 w-3" />
      Gate {gate.passed ? "passed" : "failed"}
    </span>
  );
}
