import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ReportForm } from "../../report-form";

export const metadata = { title: "Edit report · Pulse Intelligence" };

export default async function EditReportPage(props: {
  params: Promise<{ id: string }>;
}) {
  await requireRole("ANALYST");
  const { id } = await props.params;

  const report = await db.report.findUnique({ where: { id } });
  if (!report) notFound();

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title={`Edit ${report.title}`} />
      <ReportForm report={report} />
    </div>
  );
}
