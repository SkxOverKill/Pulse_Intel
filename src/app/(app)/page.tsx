import Link from "next/link";
import {
  Database,
  FileText,
  Radar,
  Rss,
  ShieldAlert,
  Target,
  Users,
} from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";

export const metadata = { title: "Dashboard · Pulse Intelligence" };

async function getCounts() {
  const [actors, campaigns, indicators, reports, techniques, sources, kev] =
    await Promise.all([
      db.threatActor.count(),
      db.campaign.count({ where: { status: "ACTIVE" } }),
      db.indicator.count({ where: { whitelisted: false } }),
      db.report.count(),
      db.technique.count(),
      db.source.count({ where: { enabled: true } }),
      db.vulnerability.count({ where: { knownExploited: true } }),
    ]);
  return { actors, campaigns, indicators, reports, techniques, sources, kev };
}

const TILES = [
  { key: "actors", label: "Threat actors", icon: Users },
  { key: "campaigns", label: "Active campaigns", icon: Target },
  { key: "indicators", label: "Indicators", icon: Database },
  { key: "kev", label: "Known exploited CVEs", icon: ShieldAlert },
  { key: "techniques", label: "ATT&CK techniques", icon: Radar },
  { key: "reports", label: "Reports", icon: FileText },
  { key: "sources", label: "Enabled feeds", icon: Rss },
] as const;

export default async function DashboardPage() {
  const user = await requireUser();
  const counts = await getCounts();
  const empty = Object.values(counts).every((n) => n === 0);

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">
          Welcome back, {user.name.split(" ")[0]}
        </h1>
        <p className="mt-1 text-sm text-ink-muted">
          Platform overview. Counts are live from the database.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {TILES.map((tile) => {
          const Icon = tile.icon;
          return (
            <Card key={tile.key} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-xs text-ink-muted">{tile.label}</p>
                  <p className="tabular mt-1.5 text-2xl font-semibold text-ink">
                    {counts[tile.key].toLocaleString()}
                  </p>
                </div>
                <span className="grid size-8 shrink-0 place-items-center rounded-md bg-surface-2 text-ink-faint">
                  <Icon className="size-4" />
                </span>
              </div>
            </Card>
          );
        })}
      </div>

      {empty ? (
        <Card>
          <CardHeader
            title="No intelligence yet"
            hint="Phase 1 of 8 complete — foundation, auth, and schema"
          />
          <EmptyState
            title="The platform is running, but empty"
            description="Threat actors, campaigns, and IOCs get their management UI in Phase 2. ATT&CK data lands in Phase 3, and feeds start filling this automatically in Phase 5."
            action={
              <Link
                href="/settings"
                className="inline-block rounded-md border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink-muted"
              >
                Settings (Phase 7)
              </Link>
            }
          />
        </Card>
      ) : null}
    </div>
  );
}
