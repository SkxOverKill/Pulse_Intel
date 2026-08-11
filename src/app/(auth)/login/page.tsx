import { redirect } from "next/navigation";
import { Radar } from "lucide-react";
import { getCurrentUser } from "@/lib/auth/dal";
import { LoginForm } from "./login-form";

export const dynamic = "force-dynamic";
export const metadata = { title: "Sign in - Pulse Intelligence" };

export default async function LoginPage(props: {
  searchParams: Promise<{ next?: string }>;
}) {
  const { next } = await props.searchParams;

  if (await getCurrentUser()) redirect("/");

  return (
    <main className="grid min-h-dvh place-items-center bg-base px-4">
      <div className="w-full max-w-sm">
        <div className="mb-7 flex flex-col items-center gap-3 text-center">
          <span className="grid size-11 place-items-center rounded-xl bg-brand/15 text-brand">
            <Radar className="size-6" strokeWidth={2.25} />
          </span>
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-ink">
              Pulse Intelligence
            </h1>
            <p className="mt-1 text-sm text-ink-muted">
              Sign in to the threat intelligence platform
            </p>
          </div>
        </div>

        <LoginForm next={next} />
      </div>
    </main>
  );
}
