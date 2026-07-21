"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";
import { Search, X } from "lucide-react";

/**
 * Filters live in the URL rather than component state so a filtered view is
 * shareable and survives a refresh — analysts pass these links around.
 */
export function ActorFilters() {
  const router = useRouter();
  const params = useSearchParams();
  const [pending, startTransition] = useTransition();

  const update = (key: string, value: string) => {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    // Any filter change invalidates the current page number.
    next.delete("page");
    startTransition(() => router.push(`/actors?${next.toString()}`));
  };

  const active = params.get("active") ?? "";
  const motivation = params.get("motivation") ?? "";
  const q = params.get("q") ?? "";
  const anyFilter = Boolean(q || active || motivation);

  const control =
    "rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink focus:border-brand focus:outline-none";

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
      <form
        className="relative min-w-56 flex-1"
        onSubmit={(e) => {
          e.preventDefault();
          const value = new FormData(e.currentTarget).get("q");
          update("q", String(value ?? ""));
        }}
      >
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-ink-faint" />
        <input
          name="q"
          type="search"
          defaultValue={q}
          placeholder="Search name, alias, description…"
          className={`${control} w-full pl-8`}
        />
      </form>

      <select
        value={motivation}
        onChange={(e) => update("motivation", e.target.value)}
        className={control}
      >
        <option value="">All motivations</option>
        <option value="ESPIONAGE">Espionage</option>
        <option value="FINANCIAL">Financial</option>
        <option value="HACKTIVISM">Hacktivism</option>
        <option value="DESTRUCTION">Destruction</option>
        <option value="INFORMATION_OPS">Information ops</option>
        <option value="UNKNOWN">Unknown</option>
      </select>

      <select
        value={active}
        onChange={(e) => update("active", e.target.value)}
        className={control}
      >
        <option value="">Any status</option>
        <option value="true">Active</option>
        <option value="false">Inactive</option>
      </select>

      {anyFilter ? (
        <button
          type="button"
          onClick={() => startTransition(() => router.push("/actors"))}
          className="inline-flex items-center gap-1 rounded-md border border-line px-2.5 py-1.5 text-sm text-ink-muted hover:bg-surface-2 hover:text-ink"
        >
          <X className="size-3.5" />
          Clear
        </button>
      ) : null}

      {pending ? <span className="text-xs text-ink-faint">Loading…</span> : null}
    </div>
  );
}
