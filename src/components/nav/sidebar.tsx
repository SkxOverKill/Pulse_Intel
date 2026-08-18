"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bug,
  Crosshair,
  Database,
  FileText,
  Gauge,
  Globe,
  Newspaper,
  Radar,
  Rss,
  Settings,
  ShieldAlert,
  Target,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";

type NavItem = {
  href: string;
  label: string;
  icon: typeof Gauge;
  /// Phases 2+ are visible but inert, so the shape of the platform is legible
  /// from day one instead of appearing piecemeal.
  soon?: boolean;
};

const SECTIONS: { heading: string; items: NavItem[] }[] = [
  {
    heading: "Overview",
    items: [
      { href: "/", label: "Dashboard", icon: Gauge },
      { href: "/news", label: "Threat News", icon: Newspaper },
    ],
  },
  {
    heading: "Intelligence",
    items: [
      { href: "/actors", label: "Threat Actors", icon: Users },
      { href: "/campaigns", label: "Campaigns", icon: Target },
      { href: "/malware", label: "Malware & Tools", icon: Bug },
      { href: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    heading: "Indicators",
    items: [
      { href: "/indicators", label: "IOCs", icon: Database },
      { href: "/enrichment", label: "Enrichment", icon: Activity },
      { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
    ],
  },
  {
    heading: "Operations",
    items: [
      { href: "/attack", label: "ATT&CK Matrix", icon: Radar },
      { href: "/hunting", label: "Threat Hunting", icon: Crosshair },
      { href: "/feeds", label: "Feeds", icon: Rss },
    ],
  },
  {
    heading: "System",
    items: [
      { href: "/settings", label: "Settings", icon: Settings },
      { href: "/audit", label: "Audit Log", icon: Globe },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <nav className="flex h-full w-60 shrink-0 flex-col border-r border-line bg-surface">
      <div className="flex items-center gap-2.5 border-b border-line px-4 py-3.5">
        <span className="grid size-8 shrink-0 place-items-center">
          <Image src="/logo.png" alt="" width={32} height={32} priority />
        </span>
        <span className="leading-tight">
          <span className="block text-sm font-semibold tracking-tight text-ink">
            Pulse Intelligence
          </span>
          <span className="block text-[11px] text-ink-faint">Threat Platform</span>
        </span>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-3">
        {SECTIONS.map((section) => (
          <div key={section.heading} className="mb-4">
            <p className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-[#454b56]">
              {section.heading}
            </p>
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const active =
                  item.href === "/"
                    ? pathname === "/"
                    : pathname.startsWith(item.href);
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-disabled={item.soon}
                      className={cn(
                        "group relative flex items-center gap-2.5 rounded-[7px] px-2.5 py-1.5 text-sm transition-colors",
                        active
                          ? "bg-brand/12 text-ink"
                          : "text-ink-muted hover:bg-surface-2 hover:text-ink",
                        item.soon && "cursor-default opacity-55 hover:bg-transparent",
                      )}
                      onClick={(e) => {
                        if (item.soon) e.preventDefault();
                      }}
                    >
                      {active ? (
                        <span className="absolute -left-2 top-1 bottom-1 w-[2.5px] rounded-full bg-brand" />
                      ) : null}
                      <Icon
                        className={cn(
                          "size-4 shrink-0",
                          active ? "text-brand" : "text-ink-faint group-hover:text-ink-muted",
                        )}
                      />
                      <span className="truncate">{item.label}</span>
                      {item.soon ? (
                        <span className="ml-auto rounded bg-surface-3 px-1 py-px text-[9px] font-medium uppercase tracking-wide text-ink-faint">
                          Soon
                        </span>
                      ) : null}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </nav>
  );
}
