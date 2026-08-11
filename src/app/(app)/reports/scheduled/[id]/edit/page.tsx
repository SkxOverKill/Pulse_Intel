import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ScheduleForm } from "../../schedule-form";

export const metadata = { title: "Edit scheduled report · Pulse Intelligence" };

export default async function EditScheduledReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  await requireRole("ANALYST");
  const { id } = await params;

  const report = await db.scheduledReport.findUnique({ where: { id } });
  if (!report) notFound();

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Edit scheduled report" description={report.name} />
      <ScheduleForm report={report} />
    </div>
  );
}
