import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { CampaignForm } from "../campaign-form";

export const metadata = { title: "New campaign · Pulse Intelligence" };

export default async function NewCampaignPage() {
  await requireRole("ANALYST");

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New campaign"
        description="Create the campaign first, then attribute it to an actor once you have grounds to."
      />
      <CampaignForm />
    </div>
  );
}
