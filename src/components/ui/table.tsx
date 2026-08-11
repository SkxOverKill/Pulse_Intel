import Link from "next/link";
import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  );
}

export function Th({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  return (
    <th
      className={cn(
        "sticky top-0 z-[2] border-b border-line bg-surface px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-ink-faint",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  return (
    <td className={cn("border-b border-line/60 px-3 py-2.5 align-middle", className)}>
      {children}
    </td>
  );
}

export function Tr({
  children,
  href,
}: {
  children: ReactNode;
  href?: string;
}) {
  // Rows are not wrapped in <a> — that would be invalid inside <tbody>. The
  // first cell carries the link; the row highlight is purely visual.
  return (
    <tr className={cn("group", href && "cursor-pointer hover:bg-white/[0.025]")}>
      {children}
    </tr>
  );
}

/**
 * Pagination that preserves existing filters. Building hrefs from the current
 * searchParams means adding a filter later doesn't silently break paging.
 */
export function Pagination({
  page,
  pageSize,
  total,
  searchParams,
  basePath,
}: {
  page: number;
  pageSize: number;
  total: number;
  searchParams: Record<string, string | undefined>;
  basePath: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total === 0) return null;

  const hrefFor = (p: number) => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(searchParams)) {
      if (v && k !== "page") params.set(k, v);
    }
    if (p > 1) params.set("page", String(p));
    const qs = params.toString();
    return qs ? `${basePath}?${qs}` : basePath;
  };

  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  return (
    <div className="flex items-center justify-between gap-4 border-t border-line px-3 py-2.5">
      <p className="tabular text-xs text-ink-muted">
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </p>
      <div className="flex items-center gap-1">
        <PageLink href={hrefFor(page - 1)} disabled={page <= 1} label="Previous">
          <ChevronLeft className="size-4" />
        </PageLink>
        <span className="tabular px-2 text-xs text-ink-muted">
          {page} / {pages}
        </span>
        <PageLink href={hrefFor(page + 1)} disabled={page >= pages} label="Next">
          <ChevronRight className="size-4" />
        </PageLink>
      </div>
    </div>
  );
}

function PageLink({
  href,
  disabled,
  label,
  children,
}: {
  href: string;
  disabled: boolean;
  label: string;
  children: ReactNode;
}) {
  const cls =
    "grid size-7 place-items-center rounded border border-line text-ink-muted transition-colors";
  if (disabled) {
    return (
      <span aria-disabled className={cn(cls, "opacity-40")} aria-label={label}>
        {children}
      </span>
    );
  }
  return (
    <Link href={href} aria-label={label} className={cn(cls, "hover:bg-surface-2 hover:text-ink")}>
      {children}
    </Link>
  );
}
