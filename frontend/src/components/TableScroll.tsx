import type { ReactNode } from "react";

/** Keyboard users can scroll wide data tables without expanding the mobile viewport. */
export default function TableScroll({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      className="overflow-x-auto print:overflow-visible"
    >
      {children}
    </div>
  );
}
