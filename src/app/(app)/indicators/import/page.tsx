import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ImportForm } from "./import-form";

export const metadata = { title: "Bulk import · Pulse Intelligence" };

export default async function ImportPage() {
  await requireRole("ANALYST");

  const sources = await db.source.findMany({
    where: { enabled: true },
    orderBy: { name: "asc" },
    select: { id: true, name: true },
  });

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="Bulk import indicators"
        description="Paste indicators one per line, or comma/tab separated. Defanged values are accepted."
      />
      <ImportForm sources={sources} />
    </div>
  );
}
