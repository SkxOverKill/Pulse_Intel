import Link from "next/link";
import { Download } from "lucide-react";
import type { AttackDomain } from "@/generated/prisma/enums";
import { requireUser } from "@/lib/auth/dal";
import { getMatrix } from "@/lib/attack/matrix";
import { Card, EmptyState } from "@/components/ui/primitives";
import { PageHeader } from "@/components/ui/page";
import { MatrixGrid } from "./matrix-grid";

export const metadata = { title: "ATT&CK Matrix · Pulse Intelligence" };

const DOMAINS: { key: AttackDomain; label: string }[] = [
  { key: "ENTERPRISE", label: "Enterprise" },
  { key: "MOBILE", label: "Mobile" },
  { key: "ICS", label: "ICS" },
];

export default async function AttackPage(props: {
  searchParams: Promise<{ domain?: string }>;
}) {
  await requireUser();
  const params = await props.searchParams;

  const domain = (
    DOMAINS.some((d) => d.key === params.domain) ? params.domain : "ENTERPRISE"
  ) as AttackDomain;

  const { columns, totalTechniques, coveredTechniques, attackVersion } =
    await getMatrix(domain);

  const pct =
    totalTechniques > 0
      ? Math.round((coveredTechniques / totalTechniques) * 100)
      : 0;

  return (
    <div className="mx-auto max-w-[100rem]">
      <PageHeader
        title="ATT&CK Matrix"
        description={
          attackVersion
            ? `MITRE ATT&CK v${attackVersion} · ${totalTechniques} techniques · ${coveredTechniques} used by tracked actors (${pct}%)`
            : "Not yet synced."
        }
        action={
          totalTechniques > 0 ? (
            <a
              href={`/api/attack/navigator?domain=${domain}`}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
            >
              <Download className="size-4" />
              Navigator layer
            </a>
          ) : null
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {DOMAINS.map((d) => (
          <Link
            key={d.key}
            href={`/attack?domain=${d.key}`}
            className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
              d.key === domain
                ? "bg-brand/15 text-ink"
                : "border border-line bg-surface text-ink-muted hover:bg-surface-2 hover:text-ink"
            }`}
          >
            {d.label}
          </Link>
        ))}
      </div>

      {totalTechniques === 0 ? (
        <Card>
          <EmptyState
            title="ATT&CK data not synced"
            description="Run `npm run attack:sync` to pull MITRE ATT&CK v19.1. The version is pinned deliberately so mappings never shift underneath you."
          />
        </Card>
      ) : (
        <MatrixGrid columns={columns} />
      )}
    </div>
  );
}
