import type { Metadata } from "next";
import { requireUser } from "@/lib/auth/dal";
import { Card, CardHeader } from "@/components/ui/primitives";
import { PageHeader } from "@/components/ui/page";
import { PasswordChangeForm } from "./password-form";

export const metadata: Metadata = {
  title: "Change password · Pulse Intelligence",
};

export default async function ChangePasswordPage() {
  const user = await requireUser();
  const demoMode = process.env.PULSE_DEMO_MODE === "1";

  return (
    <div className="mx-auto max-w-xl">
      <PageHeader
        title="Change password"
        description={`Signed in as ${user.email}. Other sessions are signed out when you change your password.`}
      />

      <Card>
        <CardHeader title="Password" hint="Argon2id hashed, min 12 characters." />
        {demoMode ? (
          <p className="text-sm text-ink-muted">
            Password changes are disabled in demo mode.
          </p>
        ) : (
          <PasswordChangeForm />
        )}
      </Card>
    </div>
  );
}