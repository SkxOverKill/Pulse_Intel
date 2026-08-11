import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ActorForm } from "../actor-form";

export const metadata = { title: "New actor · Pulse Intelligence" };

export default async function NewActorPage() {
  await requireRole("ANALYST");

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New threat actor"
        description="Aliases, techniques and indicators are linked after the actor exists."
      />
      <ActorForm />
    </div>
  );
}
