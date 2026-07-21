import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { SourceForm } from "../source-form";

export const metadata = { title: "New source · Pulse Intelligence" };

export default async function NewSourcePage() {
  await requireRole("ADMIN");

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New source"
        description="Sources set the default confidence, TLP and decay for every indicator that arrives through them."
      />
      <SourceForm />
    </div>
  );
}
