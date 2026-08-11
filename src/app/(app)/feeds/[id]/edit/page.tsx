import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { SourceForm } from "../../source-form";

export const metadata = { title: "Edit source · Pulse Intelligence" };

export default async function EditSourcePage(props: {
  params: Promise<{ id: string }>;
}) {
  await requireRole("ADMIN");
  const { id } = await props.params;

  const source = await db.source.findUnique({ where: { id } });
  if (!source) notFound();

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title={`Edit ${source.name}`} />
      <SourceForm source={source} />
    </div>
  );
}
