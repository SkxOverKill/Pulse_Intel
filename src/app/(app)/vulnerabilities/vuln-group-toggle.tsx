"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

/// Wraps the collapsed rows of a clubbed product group (e.g. "Linux Kernel —
/// 14 more"). The lead row for the group renders separately, outside this
/// component, so it's always visible.
export function VulnGroupToggle({
  label,
  count,
  children,
}: {
  label: string;
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr>
        <td colSpan={6} className="border-b border-line/60 bg-surface-2/40 px-3 py-1.5">
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="inline-flex items-center gap-1.5 text-xs text-ink-muted transition-colors hover:text-ink"
          >
            {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
            {open ? "Hide" : "Show"} {count} more {label} CVE{count === 1 ? "" : "s"}
          </button>
        </td>
      </tr>
      {open ? children : null}
    </>
  );
}
