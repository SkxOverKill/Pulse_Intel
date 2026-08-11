"use client";

import { useMemo, useRef, useState } from "react";
import { Plus } from "lucide-react";
import { linkTechnique } from "../actions";

type Option = { id: string; attackId: string; name: string };

/**
 * Technique picker.
 *
 * The full enterprise matrix is ~700 techniques, so this filters client-side
 * over a list the server already sent rather than round-tripping per keystroke.
 * At this size that is far cheaper than a search endpoint.
 */
export function TechniqueMapper({
  actorId,
  options,
}: {
  actorId: string;
  options: Option[];
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<Option | null>(null);
  const [confidence, setConfidence] = useState(50);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options.slice(0, 40);
    return options
      .filter(
        (o) =>
          o.attackId.toLowerCase().includes(q) || o.name.toLowerCase().includes(q),
      )
      .slice(0, 40);
  }, [options, query]);

  if (!open) {
    return (
      <div className="border-t border-line px-4 py-3">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink-muted transition-colors hover:bg-surface-3 hover:text-ink"
        >
          <Plus className="size-4" />
          Map a technique
        </button>
      </div>
    );
  }

  return (
    <form
      ref={formRef}
      action={async (fd) => {
        await linkTechnique(fd);
        formRef.current?.reset();
        setPicked(null);
        setQuery("");
        setConfidence(50);
        setOpen(false);
      }}
      className="space-y-2 border-t border-line px-4 py-3"
    >
      <input type="hidden" name="actorId" value={actorId} />
      <input type="hidden" name="techniqueId" value={picked?.id ?? ""} />

      <input
        type="search"
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setPicked(null);
        }}
        placeholder="Filter by ATT&CK ID or name — T1566, phishing…"
        className="w-full rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
      />

      {picked ? (
        <p className="rounded-md border border-brand/40 bg-brand/10 px-2.5 py-1.5 text-xs text-ink">
          <span className="font-mono">{picked.attackId}</span> · {picked.name}
        </p>
      ) : (
        <ul className="max-h-48 overflow-y-auto rounded-md border border-line bg-base">
          {matches.length === 0 ? (
            <li className="px-2.5 py-2 text-xs text-ink-faint">No matches.</li>
          ) : (
            matches.map((o) => (
              <li key={o.id}>
                <button
                  type="button"
                  onClick={() => {
                    setPicked(o);
                    setQuery(`${o.attackId} ${o.name}`);
                  }}
                  className="flex w-full items-baseline gap-2 px-2.5 py-1.5 text-left hover:bg-surface-2"
                >
                  <span className="font-mono text-[11px] text-ink-faint">
                    {o.attackId}
                  </span>
                  <span className="truncate text-xs text-ink">{o.name}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-ink-muted">
          Confidence
          <input
            type="range"
            name="confidence"
            min={0}
            max={100}
            step={5}
            value={confidence}
            onChange={(e) => setConfidence(Number(e.target.value))}
            className="h-1.5 w-24 cursor-pointer appearance-none rounded-full bg-surface-3 accent-brand"
          />
          <span className="tabular w-8 text-right">{confidence}%</span>
        </label>

        <input
          name="notes"
          placeholder="Optional note — why you believe this"
          className="min-w-40 flex-1 rounded-md border border-line bg-base px-2.5 py-1.5 text-xs text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
        />

        <button
          type="submit"
          disabled={!picked}
          className="rounded-md bg-brand px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-50"
        >
          Map
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setPicked(null);
            setQuery("");
          }}
          className="rounded-md border border-line px-3 py-1.5 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
