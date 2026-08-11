import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { CampaignForm } from "../../campaign-form";

export const metadata = { title: "Edit campaign · Pulse Intelligence" };

export default async function EditCampaignPage(props: {
  params: Promise<{ id: string }>;
}) {
  await requireRole("ANALYST");
  const { id } = await props.params;

  const campaign = await db.campaign.findUnique({ where: { id } });
  if (!campaign) notFound();

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title={`Edit ${campaign.name}`} />
      <CampaignForm campaign={campaign} />
    </div>
  );
}
