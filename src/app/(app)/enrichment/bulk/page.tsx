import Link from "next/link";
import { requireRole } from "@/lib/auth/dal";
import { PageHeader } from "@/components/ui/page";
import { PROVIDERS } from "@/lib/enrichment/registry";
import { loadCredentialCache } from "@/lib/enrichment/secrets";
import { BulkLookupForm } from "./bulk-form";

export const metadata = { title: "Bulk lookup · Pulse Intelligence" };

export default async function BulkLookupPage() {
  await requireRole("ANALYST");

  await loadCredentialCache();

  const providers = PROVIDERS.filter(
    (p) => p.isConfigured() && (p.name === "abuseipdb" || p.name === "virustotal"),
  ).map((p) => ({ name: p.name, label: p.label }));

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-1 flex items-center gap-2 text-xs text-ink-faint">
        <Link href="/enrichment" className="hover:text-ink-muted">
          Enrichment
        </Link>
        <span>/</span>
      </div>
      <PageHeader
        title="Bulk lookup"
        description="Paste indicators one per line to check them against AbuseIPDB and VirusTotal at once. Results include every field each provider returns, and can be exported as CSV."
      />
      <BulkLookupForm providers={providers} />
    </div>
  );
}
