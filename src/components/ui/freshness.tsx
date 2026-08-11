/**
 * FreshnessBar — visual indicator of how current an IOC is.
 *
 * Analysts need to know at a glance whether an indicator is fresh intel
 * or stale data from six months ago. A stale IP in a blocklist is noise.
 * A stale hash in an EDR rule wastes cycles. This component makes age
 * immediately visible without requiring date arithmetic in the analyst's head.
 *
 * The bar shows how much of the indicator's configured half-life remains.
 * No expiresAt = never expires = always shows as 100% fresh (green).
 *
 * Color progression:
 *   > 75% remaining → green (fresh)
 *   50-75%          → yellow-green
 *   25-50%          → amber (aging)
 *   10-25%          → orange (stale)
 *   < 10%           → red (expired or nearly so)
 */

type Props = {
  firstSeen: Date;
  lastSeen: Date;
  expiresAt: Date | null;
  /** Show the exact last-seen date as text alongside the bar. Default false. */
  showDate?: boolean;
};

function freshnessColor(pct: number): string {
  if (pct >= 75) return "bg-ok";
  if (pct >= 50) return "bg-[#84cc16]"; // lime
  if (pct >= 25) return "bg-warn";
  if (pct >= 10) return "bg-orange-500";
  return "bg-danger";
}

function daysSince(date: Date): number {
  return Math.round((Date.now() - date.getTime()) / 86_400_000);
}

export function FreshnessBar({ firstSeen, lastSeen, expiresAt, showDate = false }: Props) {
  const now = new Date();

  // No expiry = never decays = always fresh.
  if (!expiresAt) {
    return (
      <div className="flex items-center gap-2" title="No expiry configured — indicator does not decay">
        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3">
          <div className="h-full w-full rounded-full bg-ok" />
        </div>
        {showDate ? (
          <span className="tabular text-[11px] text-ink-faint">
            {lastSeen.toISOString().slice(0, 10)}
          </span>
        ) : null}
      </div>
    );
  }

  const totalMs = expiresAt.getTime() - firstSeen.getTime();
  const remainingMs = expiresAt.getTime() - now.getTime();
  const pct = totalMs > 0 ? Math.max(0, Math.min(100, (remainingMs / totalMs) * 100)) : 0;
  const expired = remainingMs <= 0;
  const ageLabel = `${daysSince(lastSeen)}d ago`;

  const barColor = freshnessColor(pct);
  const label = expired
    ? "Expired"
    : `${Math.round(pct)}% remaining until expiry`;

  return (
    <div
      className="flex items-center gap-2"
      title={`${label} · Last seen ${ageLabel}`}
    >
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3">
        <div
          className={`h-full rounded-full transition-all ${barColor}`}
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>
      {showDate ? (
        <span className={`tabular text-[11px] ${expired ? "text-danger" : "text-ink-faint"}`}>
          {expired ? "expired" : lastSeen.toISOString().slice(0, 10)}
        </span>
      ) : null}
    </div>
  );
}
