import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { HuntBuilder } from "../hunt-builder";

export const metadata = { title: "New hunt · Pulse Intelligence" };

export default async function NewHuntPage() {
  await requireRole("ANALYST");

  const sources = await db.source.findMany({
    orderBy: { name: "asc" },
    select: { id: true, name: true },
  });

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="New hunt"
        description="Build a query over the indicator set. Save it, run it on demand, or give it a schedule to run automatically."
      />
      <HuntBuilder sources={sources} />
    </div>
  );
}
