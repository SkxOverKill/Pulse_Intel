"use client";

/**
 * ActorComparePicker — two dropdowns that navigate to /actors/compare?a=&b=
 * when both are filled. Lives in the page action area. Client-side only so the
 * navigate() can react to both selections without a server round-trip.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { GitCompare } from "lucide-react";

type ActorRef = { id: string; name: string };

export function ActorComparePicker({ actors }: { actors: ActorRef[] }) {
  const router = useRouter();
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [open, setOpen] = useState(false);

  function compare() {
    if (a && b && a !== b) {
      router.push(`/actors/compare?a=${a}&b=${b}`);
      setOpen(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-3 py-2 text-sm text-ink-muted transition-colors hover:bg-surface-3 hover:text-ink"
      >
        <GitCompare className="size-4" />
        Compare
      </button>
    );
  }

  return (
    <div className="flex items-center gap-2 rounded-md border border-line bg-surface-2 px-3 py-1.5">
      <GitCompare className="size-4 shrink-0 text-ink-faint" />
      <select
        value={a}
        onChange={(e) => setA(e.target.value)}
        className="rounded border-0 bg-transparent text-sm text-ink focus:outline-none"
        aria-label="First actor"
      >
        <option value="">Actor A…</option>
        {actors.map((ac) => (
          <option key={ac.id} value={ac.id} disabled={ac.id === b}>
            {ac.name}
          </option>
        ))}
      </select>
      <span className="text-xs text-ink-faint">vs</span>
      <select
        value={b}
        onChange={(e) => setB(e.target.value)}
        className="rounded border-0 bg-transparent text-sm text-ink focus:outline-none"
        aria-label="Second actor"
      >
        <option value="">Actor B…</option>
        {actors.map((ac) => (
          <option key={ac.id} value={ac.id} disabled={ac.id === a}>
            {ac.name}
          </option>
        ))}
      </select>
      <button
        type="button"
        onClick={compare}
        disabled={!a || !b || a === b}
        className="rounded-md bg-brand px-2.5 py-1 text-xs font-medium text-white transition-opacity disabled:opacity-40"
      >
        Compare
      </button>
      <button
        type="button"
        onClick={() => { setOpen(false); setA(""); setB(""); }}
        className="text-xs text-ink-faint hover:text-ink"
        aria-label="Cancel comparison"
      >
        ×
      </button>
    </div>
  );
}
