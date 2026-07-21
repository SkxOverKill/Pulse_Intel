import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ReportForm } from "../report-form";

export const metadata = { title: "New report · Pulse Intelligence" };

export default async function NewReportPage() {
  await requireRole("ANALYST");

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New report"
        description="Paste indicators inline; you can extract and link them once the report is saved."
      />
      <ReportForm />
    </div>
  );
}
