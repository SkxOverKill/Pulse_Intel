import Link from "next/link";
import { ShieldAlert } from "lucide-react";

export const metadata = { title: "Access denied · Pulse Intelligence" };

export default function ForbiddenPage() {
  return (
    <main className="grid min-h-dvh place-items-center bg-base px-4 text-center">
      <div className="max-w-sm">
        <span className="mx-auto mb-4 grid size-11 place-items-center rounded-xl bg-danger/15 text-danger">
          <ShieldAlert className="size-6" />
        </span>
        <h1 className="text-lg font-semibold text-ink">Access denied</h1>
        <p className="mt-1.5 text-sm text-ink-muted">
          Your role does not permit access to this area. Ask an administrator if
          you believe this is a mistake.
        </p>
        <Link
          href="/"
          className="mt-5 inline-block rounded-md border border-line bg-surface px-4 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
        >
          Back to dashboard
        </Link>
      </div>
    </main>
  );
}
