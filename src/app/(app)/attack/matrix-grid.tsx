"use client";

import Link from "next/link";
import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { MatrixColumn, MatrixTechnique } from "@/lib/attack/matrix";

/**
 * Heat is driven by how many tracked actors use a technique, not by raw
 * frequency in MITRE's data — the point of the matrix here is "what do our
 * adversaries do", not "what exists in ATT&CK".
 */
function heat(count: number): string {
  if (count === 0) return "border-line bg-surface hover:bg-surface-2";
  if (count === 1) return "border-brand/30 bg-brand/10 hover:bg-brand/15";
  if (count <= 3) return "border-brand/50 bg-brand/20 hover:bg-brand/25";
  if (count <= 6) return "border-sev-high/50 bg-sev-high/20 hover:bg-sev-high/25";
  return "border-sev-critical/60 bg-sev-critical/25 hover:bg-sev-critical/30";
}

export function MatrixGrid({ columns }: { columns: MatrixColumn[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [onlyCovered, setOnlyCovered] = useState(false);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const visible = columns.map((col) => ({
    ...col,
    techniques: onlyCovered
      ? col.techniques.filter((t) => t.actorCount > 0)
      : col.techniques,
  }));

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-4">
        <label className="flex cursor-pointer items-center gap-2 text-sm text-ink-muted">
          <input
            type="checkbox"
            checked={onlyCovered}
            onChange={(e) => setOnlyCovered(e.target.checked)}
            className="size-4 rounded border-line bg-base accent-brand"
          />
          Only techniques used by tracked actors
        </label>

        <div className="flex items-center gap-2 text-xs text-ink-faint">
          <span>Actors using:</span>
          {[
            { label: "0", cls: "border-line bg-surface" },
            { label: "1", cls: "border-brand/30 bg-brand/10" },
            { label: "2–3", cls: "border-brand/50 bg-brand/20" },
            { label: "4–6", cls: "border-sev-high/50 bg-sev-high/20" },
            { label: "7+", cls: "border-sev-critical/60 bg-sev-critical/25" },
          ].map((k) => (
            <span key={k.label} className="flex items-center gap-1">
              <span className={cn("inline-block size-3 rounded-sm border", k.cls)} />
              {k.label}
            </span>
          ))}
        </div>
      </div>

      {/* The matrix is intrinsically wide; it scrolls inside its own container
          so the page body never scrolls horizontally. */}
      <div className="overflow-x-auto rounded-[--radius-card] border border-line bg-surface">
        <div className="flex min-w-max gap-px bg-line p-px">
          {visible.map((col) => (
            <div key={col.shortname} className="flex w-52 shrink-0 flex-col bg-surface">
              <div className="sticky top-0 z-10 border-b border-line bg-surface-2 px-2 py-2">
                <p className="truncate text-xs font-semibold text-ink" title={col.name}>
                  {col.name}
                </p>
                <p className="tabular text-[10px] text-ink-faint">
                  {col.techniques.length} techniques
                </p>
              </div>

              <div className="flex flex-col gap-px p-1">
                {col.techniques.map((t) => (
                  <Cell
                    key={`${col.shortname}-${t.id}`}
                    technique={t}
                    expanded={expanded.has(`${col.shortname}-${t.id}`)}
                    onToggle={() => toggle(`${col.shortname}-${t.id}`)}
                    onlyCovered={onlyCovered}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Cell({
  technique,
  expanded,
  onToggle,
  onlyCovered,
}: {
  technique: MatrixTechnique;
  expanded: boolean;
  onToggle: () => void;
  onlyCovered: boolean;
}) {
  const subs = onlyCovered
    ? technique.subtechniques.filter((s) => s.actorCount > 0)
    : technique.subtechniques;

  return (
    <div>
      <div
        className={cn(
          "group flex items-start gap-1 rounded border px-1.5 py-1 transition-colors",
          heat(technique.actorCount),
        )}
      >
        {subs.length > 0 ? (
          <button
            type="button"
            onClick={onToggle}
            aria-label={expanded ? "Collapse sub-techniques" : "Expand sub-techniques"}
            className="mt-0.5 shrink-0 text-ink-faint hover:text-ink"
          >
            <ChevronRight
              className={cn("size-3 transition-transform", expanded && "rotate-90")}
            />
          </button>
        ) : (
          <span className="w-3 shrink-0" />
        )}

        <Link href={`/attack/${technique.attackId}`} className="min-w-0 flex-1">
          <span className="block truncate text-[11px] leading-tight text-ink" title={technique.name}>
            {technique.name}
          </span>
          <span className="tabular block text-[10px] text-ink-faint">
            {technique.attackId}
            {subs.length > 0 ? ` · ${subs.length}` : ""}
            {technique.actorCount > 0 ? ` · ${technique.actorCount} actor${technique.actorCount === 1 ? "" : "s"}` : ""}
          </span>
        </Link>
      </div>

      {expanded && subs.length > 0 ? (
        <div className="ml-3 mt-px flex flex-col gap-px border-l border-line pl-1">
          {subs.map((s) => (
            <Link
              key={s.id}
              href={`/attack/${s.attackId}`}
              className={cn(
                "rounded border px-1.5 py-1 transition-colors",
                heat(s.actorCount),
              )}
            >
              <span className="block truncate text-[11px] leading-tight text-ink" title={s.name}>
                {s.name}
              </span>
              <span className="tabular block text-[10px] text-ink-faint">
                {s.attackId}
                {s.actorCount > 0 ? ` · ${s.actorCount}` : ""}
              </span>
            </Link>
          ))}
        </div>
      ) : null}
    </div>
  );
}
