/**
 * Chart primitives for the dashboard. Hand-rolled SVG rather than a charting
 * library — the app has no chart dependency, the shapes needed here (a
 * labeled horizontal bar list, a single-series day trend) are simple enough
 * not to need one, and it keeps the bundle and the visual language identical
 * to the rest of the UI (ConfidenceBar already does the same "styled div/SVG
 * bar" thing for a single value).
 *
 * Mark specs and the categorical palette follow the project's dataviz skill:
 * thin marks, rounded data-end, a 2px surface ring on trend end-markers, and
 * — the part that's actually load-bearing — colors are never picked by eye.
 * `--color-chart-1..6` in globals.css were run through the skill's palette
 * validator against this app's real dark surface before being used here.
 *
 * No "use client" here deliberately: this component has no interactivity, so
 * it stays server-rendered — which also means a Server Component parent can
 * pass it a plain `formatValue` function prop. `TrendArea` (trend-area.tsx)
 * needs hover state, so it's a separate client-only file; if this file picked
 * up "use client" too, every prop passed to it from a server page would have
 * to be serializable, and a function prop is not.
 */

export type BarDatum = {
  label: string;
  value: number;
  /** Defaults to the categorical chart palette in fixed slot order. Pass an
   *  explicit status/severity token (e.g. "var(--color-sev-critical)") when
   *  the dimension already has a reserved status color — never invent a new
   *  categorical hue for something severity/TLP/status already owns. */
  color?: string;
  href?: string;
};

const CATEGORICAL_SLOTS = [
  "var(--color-chart-1)",
  "var(--color-chart-2)",
  "var(--color-chart-3)",
  "var(--color-chart-4)",
  "var(--color-chart-5)",
  "var(--color-chart-6)",
];

function formatCompact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

/**
 * A labeled horizontal bar list — for comparing a handful of categories by
 * magnitude (severity mix, indicator types, ATT&CK tactic coverage). Each row
 * is directly labeled, so this counts as a single encoded series per the
 * skill's legend rule ("a single series needs no legend box") even though
 * multiple categories are shown — the row label carries identity, not a
 * shared color-to-name legend.
 */
export function HorizontalBarChart({
  data,
  formatValue = formatCompact,
  emptyLabel = "No data yet",
}: {
  data: BarDatum[];
  formatValue?: (n: number) => string;
  emptyLabel?: string;
}) {
  if (data.length === 0) {
    return <p className="px-4 py-8 text-center text-sm text-ink-faint">{emptyLabel}</p>;
  }

  const max = Math.max(...data.map((d) => d.value), 1);

  return (
    <div className="space-y-2.5 px-4 py-3">
      {data.map((d, i) => {
        const pct = Math.max((d.value / max) * 100, d.value > 0 ? 2 : 0);
        const color = d.color ?? CATEGORICAL_SLOTS[i % CATEGORICAL_SLOTS.length];
        const row = (
          <div className="flex items-center gap-3">
            <span className="w-28 shrink-0 truncate text-xs text-ink-muted" title={d.label}>
              {d.label}
            </span>
            <span className="h-4 flex-1 overflow-hidden rounded-sm bg-surface-3">
              <span
                className="block h-full rounded-r-[3px]"
                style={{ width: `${pct}%`, backgroundColor: color }}
              />
            </span>
            <span className="tabular w-12 shrink-0 text-right text-xs text-ink-muted">
              {formatValue(d.value)}
            </span>
          </div>
        );
        return d.href ? (
          <a key={d.label} href={d.href} className="block rounded transition-colors hover:bg-surface-2">
            {row}
          </a>
        ) : (
          <div key={d.label}>{row}</div>
        );
      })}
    </div>
  );
}
