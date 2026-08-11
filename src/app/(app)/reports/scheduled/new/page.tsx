import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { ScheduleForm } from "../schedule-form";

export const metadata = { title: "New scheduled report · Pulse Intelligence" };

export default async function NewScheduledReportPage() {
  await requireRole("ANALYST");

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New scheduled report"
        description="Give it a cadence and it files a summary report automatically, every time it runs."
      />
      <ScheduleForm />
    </div>
  );
}
