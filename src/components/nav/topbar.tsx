import { LogOut, Search } from "lucide-react";
import type { CurrentUser } from "@/lib/auth/dal";
import { logout } from "@/app/(auth)/actions";

const ROLE_LABELS: Record<CurrentUser["role"], string> = {
  ADMIN: "Admin",
  ANALYST: "Analyst",
  READONLY: "Read only",
};

export function TopBar({ user }: { user: CurrentUser }) {
  const initials = user.name
    .split(" ")
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-line bg-surface px-4">
      {/* A plain GET form — no client JS needed, and the results URL is
          shareable. Pasting an IOC redirects straight to that indicator. */}
      <form action="/search" method="get" className="relative max-w-md flex-1">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-ink-faint" />
        <input
          type="search"
          name="q"
          placeholder="Search actors, IOCs, techniques…"
          className="w-full rounded-md border border-line bg-base py-1.5 pl-8 pr-3 text-sm text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
        />
      </form>

      <div className="ml-auto flex items-center gap-3">
        <div className="text-right leading-tight">
          <p className="text-sm text-ink">{user.name}</p>
          <p className="text-[11px] text-ink-faint">{ROLE_LABELS[user.role]}</p>
        </div>
        <span className="grid size-8 place-items-center rounded-full bg-brand/15 text-xs font-semibold text-brand">
          {initials}
        </span>
        <form action={logout}>
          <button
            type="submit"
            title="Sign out"
            className="grid size-8 place-items-center rounded-md text-ink-faint transition-colors hover:bg-surface-2 hover:text-ink"
          >
            <LogOut className="size-4" />
          </button>
        </form>
      </div>
    </header>
  );
}
