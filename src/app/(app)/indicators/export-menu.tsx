"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { ChevronDown, Download } from "lucide-react";
import { EXPORT_FORMATS } from "@/lib/export/formats";

/**
 * Export the current filtered view. Builds a link to the export route carrying
 * the same q/type/severity params the list is using, so the download matches
 * exactly what's on screen. (`page` is dropped — an export is the whole set,
 * not one page of it.)
 */
export function ExportMenu() {
  const params = useSearchParams();
  const [open, setOpen] = useState(false);

  function hrefFor(format: string): string {
    const next = new URLSearchParams();
    for (const key of ["q", "type", "severity"]) {
      const v = params.get(key);
      if (v) next.set(key, v);
    }
    next.set("format", format);
    return `/indicators/export?${next.toString()}`;
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
      >
        <Download className="size-4" />
        Export
        <ChevronDown className="size-3.5 text-ink-faint" />
      </button>

      {open ? (
        <div className="absolute right-0 z-10 mt-1 w-48 overflow-hidden rounded-md border border-line bg-surface shadow-lg">
          <p className="border-b border-line px-3 py-1.5 text-[10px] uppercase tracking-wide text-ink-faint">
            Export current view
          </p>
          {EXPORT_FORMATS.map((f) => (
            <a
              key={f.id}
              href={hrefFor(f.id)}
              className="block px-3 py-2 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
            >
              {f.label}
            </a>
          ))}
        </div>
      ) : null}
    </div>
  );
}
