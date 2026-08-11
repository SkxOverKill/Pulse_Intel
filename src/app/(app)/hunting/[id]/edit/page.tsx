import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { validateHuntQuery, type HuntQueryAst } from "@/lib/hunting/schema";
import { HuntBuilder } from "../../hunt-builder";

export const metadata = { title: "Edit hunt · Pulse Intelligence" };

export default async function EditHuntPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  await requireRole("ANALYST");
  const { id } = await params;

  const [hunt, sources] = await Promise.all([
    db.huntQuery.findUnique({ where: { id } }),
    db.source.findMany({ orderBy: { name: "asc" }, select: { id: true, name: true } }),
  ]);
  if (!hunt) notFound();

  const validated = validateHuntQuery(hunt.query);
  // A stored query that no longer validates (e.g. an enum was removed) opens
  // with an empty builder rather than crashing — the analyst rebuilds it.
  const ast: HuntQueryAst = validated.ok
    ? validated.ast
    : { entity: "indicator", match: "all", conditions: [] };

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader title="Edit hunt" description={hunt.name} />
      <HuntBuilder
        sources={sources}
        hunt={{
          id: hunt.id,
          name: hunt.name,
          description: hunt.description,
          schedule: hunt.schedule,
          notifyOnHit: hunt.notifyOnHit,
          ast,
        }}
      />
    </div>
  );
}
