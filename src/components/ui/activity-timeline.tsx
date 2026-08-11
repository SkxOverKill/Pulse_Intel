/**
 * ActivityTimeline — a vertical chronological event strip for a threat actor.
 *
 * Shows campaigns, indicator observations, and reported activity as a
 * single ordered timeline so analysts can see operational tempo at a glance.
 * "Went quiet in Q3 2023, resumed Q1 2024" is the kind of insight that comes
 * free from a timeline but costs minutes of pivot-clicking without one.
 *
 * Designed to render server-side with no client JS — just data → JSX.
 */

export type TimelineEvent = {
  id: string;
  date: string;          // ISO date string, day-precision (YYYY-MM-DD)
  kind: "campaign_start" | "campaign_end" | "ioc_observed" | "report" | "first_seen" | "last_seen";
  label: string;
  href?: string;
  note?: string;
};

const KIND_META: Record<
  TimelineEvent["kind"],
  { dot: string; icon: string; label: string }
> = {
  first_seen:     { dot: "bg-ok",        icon: "●", label: "First observed" },
  campaign_start: { dot: "bg-brand",     icon: "▶", label: "Campaign started" },
  ioc_observed:   { dot: "bg-warn",      icon: "◆", label: "IOC observed" },
  report:         { dot: "bg-ink-muted", icon: "📄", label: "Report" },
  campaign_end:   { dot: "bg-ink-faint", icon: "■", label: "Campaign ended" },
  last_seen:      { dot: "bg-danger",    icon: "●", label: "Last observed" },
};

/** Groups events by calendar year, most-recent first. */
function groupByYear(events: TimelineEvent[]): [string, TimelineEvent[]][] {
  const byYear = new Map<string, TimelineEvent[]>();
  for (const ev of events) {
    const year = ev.date.slice(0, 4);
    if (!byYear.has(year)) byYear.set(year, []);
    byYear.get(year)!.push(ev);
  }
  return [...byYear.entries()].sort(([a], [b]) => b.localeCompare(a));
}

export function ActivityTimeline({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="px-4 py-8 text-center text-sm text-ink-faint">
        No dated activity on record.
      </div>
    );
  }

  const sorted = [...events].sort((a, b) => b.date.localeCompare(a.date));
  const grouped = groupByYear(sorted);

  return (
    <div className="px-4 py-4">
      {grouped.map(([year, evs]) => (
        <div key={year} className="mb-6 last:mb-0">
          <div className="mb-3 flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider text-ink-faint">{year}</span>
            <div className="h-px flex-1 bg-line/50" />
          </div>

          <ol className="relative ml-2.5 border-l border-line/60">
            {evs.map((ev) => {
              const meta = KIND_META[ev.kind];
              return (
                <li key={ev.id} className="mb-4 ml-4 last:mb-0">
                  {/* dot on the timeline rail */}
                  <span
                    className={`absolute -left-[7px] mt-[3px] size-3.5 rounded-full border-2 border-base ${meta.dot}`}
                    aria-label={meta.label}
                  />
                  <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                    <time
                      dateTime={ev.date}
                      className="tabular text-[10px] text-ink-faint"
                    >
                      {ev.date.slice(5)} {/* MM-DD */}
                    </time>
                    <span className="text-[10px] text-ink-faint opacity-60">{meta.label}</span>
                  </div>
                  <p className="mt-0.5 text-sm text-ink">
                    {ev.href ? (
                      <a href={ev.href} className="hover:text-brand hover:underline">
                        {ev.label}
                      </a>
                    ) : (
                      ev.label
                    )}
                  </p>
                  {ev.note ? (
                    <p className="mt-0.5 text-xs text-ink-muted">{ev.note}</p>
                  ) : null}
                </li>
              );
            })}
          </ol>
        </div>
      ))}
    </div>
  );
}
