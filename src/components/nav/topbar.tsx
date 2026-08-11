import type { CurrentUser } from "@/lib/auth/dal";
import { CommandPalette } from "@/components/nav/command-palette";
import { logout } from "@/app/(auth)/actions";

const ROLE_LABELS: Record<CurrentUser["role"], string> = {
  ADMIN: "Admin",
  ANALYST: "Analyst",
  READONLY: "Read only",
};

export function TopBar({ user }: { user: CurrentUser }) {
  const demoMode = process.env.PULSE_DEMO_MODE === "1";
  const initials = user.name
    .split(" ")
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();

  return (
    <header className="flex h-[54px] shrink-0 items-center gap-4 border-b border-line bg-base px-5">
      <CommandPalette />

      <div className="ml-auto flex items-center gap-3">
        {demoMode ? (
          <span className="rounded border border-line bg-surface-2 px-2 py-1 text-[11px] text-ink-faint">
            Public demo
          </span>
        ) : (
          <form action={logout}>
            <button
              type="submit"
              className="rounded border border-line bg-surface-2 px-2 py-1 text-[11px] text-ink-faint transition-colors hover:border-brand/40 hover:text-ink"
            >
              Sign out
            </button>
          </form>
        )}
        <div className="text-right leading-tight">
          <p className="text-sm text-ink">{user.name}</p>
          <p className="text-[11px] text-ink-faint">{ROLE_LABELS[user.role]}</p>
        </div>
        <span className="grid size-8 place-items-center rounded-full bg-brand/15 text-xs font-semibold text-brand">
          {initials}
        </span>
      </div>
    </header>
  );
}
