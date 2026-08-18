import Link from "next/link";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { PROVIDERS } from "@/lib/enrichment/registry";
import { loadCredentialCache } from "@/lib/enrichment/secrets";
import { LookupForm } from "./lookup-form";

export const metadata = { title: "Lookup · Pulse Intelligence" };

export default async function LookupPage() {
  await requireRole("ANALYST");

  await loadCredentialCache();

  const providers = PROVIDERS.filter((p) => p.isConfigured() && p.name !== "stub").map(
    (p) => ({ name: p.name, label: p.label }),
  );

  return (
    <div className="mx-auto max-w-2xl">
      <div className="mb-1 flex items-center gap-2 text-xs text-ink-faint">
        <Link href="/enrichment" className="hover:text-ink-muted">
          Enrichment
        </Link>
        <span>/</span>
      </div>
      <PageHeader
        title="Lookup"
        description="Search a single IP, domain, URL, hash, or CVE against one or more providers right now — no need to import it as a feed indicator first."
      />
      <LookupForm providers={providers} />
    </div>
  );
}
