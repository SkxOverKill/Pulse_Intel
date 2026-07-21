"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";
import { Search, X } from "lucide-react";

const TYPES = [
  "IPV4",
  "IPV6",
  "DOMAIN",
  "URL",
  "MD5",
  "SHA1",
  "SHA256",
  "EMAIL",
  "CVE",
  "BTC_ADDRESS",
  "REGISTRY_KEY",
  "MUTEX",
  "FILENAME",
  "USER_AGENT",
  "ASN",
];

export function IndicatorFilters({ whitelistedCount }: { whitelistedCount: number }) {
  const router = useRouter();
  const params = useSearchParams();
  const [pending, startTransition] = useTransition();

  const update = (key: string, value: string) => {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("page");
    startTransition(() => router.push(`/indicators?${next.toString()}`));
  };

  const q = params.get("q") ?? "";
  const type = params.get("type") ?? "";
  const severity = params.get("severity") ?? "";
  const whitelisted = params.get("whitelisted") === "true";
  const anyFilter = Boolean(q || type || severity || whitelisted);

  const control =
    "rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink focus:border-brand focus:outline-none";

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
      <form
        className="relative min-w-56 flex-1"
        onSubmit={(e) => {
          e.preventDefault();
          update("q", String(new FormData(e.currentTarget).get("q") ?? ""));
        }}
      >
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-ink-faint" />
        <input
          name="q"
          type="search"
          defaultValue={q}
          placeholder="Substring match on indicator value…"
          className={`${control} w-full pl-8`}
        />
      </form>

      <select value={type} onChange={(e) => update("type", e.target.value)} className={control}>
        <option value="">All types</option>
        {TYPES.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>

      <select
        value={severity}
        onChange={(e) => update("severity", e.target.value)}
        className={control}
      >
        <option value="">Any severity</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
        <option value="INFO">Info</option>
      </select>

      <label
        className="flex cursor-pointer items-center gap-1.5 text-sm text-ink-muted"
        title="Whitelisted indicators are stored but never exported or alerted on."
      >
        <input
          type="checkbox"
          checked={whitelisted}
          onChange={(e) => update("whitelisted", e.target.checked ? "true" : "")}
          className="size-4 rounded border-line bg-base accent-brand"
        />
        Whitelisted
        <span className="tabular text-xs text-ink-faint">({whitelistedCount})</span>
      </label>

      {anyFilter ? (
        <button
          type="button"
          onClick={() => startTransition(() => router.push("/indicators"))}
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
