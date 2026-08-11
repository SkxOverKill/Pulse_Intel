"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { SearchHit, SearchHitType } from "@/lib/search/query";

const TYPE_LABELS: Record<SearchHitType, string> = {
  actor: "Threat actor",
  campaign: "Campaign",
  indicator: "Indicator",
  report: "Report",
  technique: "Technique",
  malware: "Malware",
  tool: "Tool",
  vulnerability: "Vulnerability",
};

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const openPalette = useCallback(() => {
    setQuery("");
    setHits([]);
    setOpen(true);
  }, []);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (open) {
          setOpen(false);
        } else {
          openPalette();
        }
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, openPalette]);

  useEffect(() => {
    if (open) {
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const q = query.trim();
    if (q.length < 2) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- clear results when the debounced search becomes invalid.
      setHits([]);
      return;
    }
    setLoading(true);
    const handle = setTimeout(() => {
      fetch(`/api/search?q=${encodeURIComponent(q)}`)
        .then((r) => r.json())
        .then((data: { hits: SearchHit[] }) => setHits(data.hits ?? []))
        .catch(() => setHits([]))
        .finally(() => setLoading(false));
    }, 180);
    return () => clearTimeout(handle);
  }, [query, open]);

  const close = useCallback(() => setOpen(false), []);

  const grouped = new Map<SearchHitType, SearchHit[]>();
  for (const hit of hits) {
    const list = grouped.get(hit.type) ?? [];
    list.push(hit);
    grouped.set(hit.type, list);
  }

  return (
    <>
      <button
        type="button"
        onClick={openPalette}
        className="flex h-[33px] w-[410px] max-w-full items-center gap-2.5 rounded-lg border border-line-strong bg-surface px-3 text-left text-ink-faint shadow-[inset_0_1px_2px_rgba(0,0,0,0.25)] transition-colors hover:border-brand/40"
      >
        <span className="relative size-3.5 shrink-0 rounded-full border-[1.4px] border-ink-faint">
          <span className="absolute -bottom-[4.5px] -right-0.5 h-1.5 w-[1.4px] rotate-45 bg-ink-faint" />
        </span>
        <span className="flex-1 truncate text-[12.5px]">Search actors, IOCs, techniques, CVEs…</span>
        <span className="mono rounded border border-line-strong bg-white/[0.04] px-1.5 py-0.5 text-[10px] text-ink-muted">
          ⌘K
        </span>
      </button>

      {open ? (
        <div
          className="fixed inset-0 z-50 flex justify-center bg-black/70 pt-[120px]"
          onClick={close}
        >
          <div
            className="h-fit w-[580px] max-w-[90vw] overflow-hidden rounded-xl border border-line-strong bg-[#191c22] shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2.5 border-b border-line px-4 py-3">
              <span className="text-brand">›</span>
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") close();
                }}
                placeholder="Search actors, IOCs, techniques, CVEs…"
                className="flex-1 bg-transparent text-sm text-ink placeholder:text-ink-faint focus:outline-none"
              />
              <span className="mono rounded border border-line-strong px-1.5 py-0.5 text-[10px] text-ink-muted">
                ESC
              </span>
            </div>
            <div className="max-h-[420px] overflow-y-auto">
              {query.trim().length < 2 ? (
                <p className="px-4 py-8 text-center text-xs text-ink-faint">
                  Type at least 2 characters to search.
                </p>
              ) : loading && hits.length === 0 ? (
                <p className="px-4 py-8 text-center text-xs text-ink-faint">Searching…</p>
              ) : hits.length === 0 ? (
                <p className="px-4 py-8 text-center text-xs text-ink-faint">No matches.</p>
              ) : (
                [...grouped.entries()].map(([type, list]) => (
                  <div key={type} className="border-b border-line/60 last:border-0">
                    <p className="px-4 pt-2.5 pb-1 text-[10px] font-medium uppercase tracking-wider text-ink-faint">
                      {TYPE_LABELS[type]}
                    </p>
                    {list.map((hit) => (
                      <button
                        key={`${hit.type}-${hit.id}`}
                        type="button"
                        onClick={() => {
                          close();
                          router.push(hit.href);
                        }}
                        className="flex w-full items-baseline gap-3 px-4 py-2 text-left hover:bg-white/[0.04]"
                      >
                        <span className="min-w-0 flex-1 truncate text-[13px] text-ink">
                          {hit.title}
                        </span>
                        {hit.subtitle ? (
                          <span className="shrink-0 truncate text-[11px] text-ink-faint">
                            {hit.subtitle}
                          </span>
                        ) : null}
                      </button>
                    ))}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
