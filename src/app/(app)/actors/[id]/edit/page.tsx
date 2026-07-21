import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ActorForm } from "../../actor-form";

export const metadata = { title: "Edit actor · Pulse Intelligence" };

export default async function EditActorPage(props: {
  params: Promise<{ id: string }>;
}) {
  await requireRole("ANALYST");
  const { id } = await props.params;

  const actor = await db.threatActor.findUnique({ where: { id } });
  if (!actor) notFound();

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title={`Edit ${actor.name}`} />
      <ActorForm actor={actor} />
    </div>
  );
}
