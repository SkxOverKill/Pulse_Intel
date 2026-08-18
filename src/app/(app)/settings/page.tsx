import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth/dal";
import { Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Muted, PageHeader, Tag } from "@/components/ui/page";
import { CreateKeyForm } from "./create-key-form";
import { ProviderKeyRow } from "./provider-key-row";
import { revokeApiKey } from "./actions";
import { CREDENTIAL_CATALOG, loadCredentialCache, secretOrigin } from "@/lib/enrichment/secrets";

export const metadata = { title: "Settings · Pulse Intelligence" };

export default async function SettingsPage() {
  await requireRole("ADMIN");

  const keys = await db.apiKey.findMany({
    orderBy: { createdAt: "desc" },
    include: { user: { select: { name: true } } },
  });

  // Decrypt DB-stored provider keys so secretOrigin() can tell Settings-set
  // keys apart from env keys.
  await loadCredentialCache();
  const credentials = CREDENTIAL_CATALOG.map((c) => ({
    ...c,
    origin: secretOrigin(c.provider),
  }));

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Settings"
        description="API keys for the public REST API, and provider keys stored here are used before .env — set one way, not both."
      />

      <div className="space-y-4">
        <CreateKeyForm />

        <Card>
          <CardHeader
            title="Provider credentials"
            hint="Keys set here are encrypted at rest (CREDENTIAL_ENC_KEY) and take precedence over the same key in .env. The worker picks them up automatically."
          />
          {credentials.map((c) => (
            <ProviderKeyRow key={c.provider} row={c} />
          ))}
        </Card>

        <Card>
          <CardHeader
            title="API keys"
            hint="Bearer tokens for /api/v1 — see the docs link on each endpoint's 401 response."
          />
          {keys.length === 0 ? (
            <EmptyState
              title="No API keys yet"
              description="Create one above to use the public REST API programmatically."
            />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Key</Th>
                  <Th>Scopes</Th>
                  <Th>Created by</Th>
                  <Th>Last used</Th>
                  <Th>Status</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <Tr key={k.id}>
                    <Td className="font-medium text-ink">{k.name}</Td>
                    <Td>
                      <code className="font-mono text-xs text-ink-muted">{k.prefix}…</code>
                    </Td>
                    <Td>
                      {k.scopes.length === 0 ? (
                        <span className="text-xs text-warn">full access</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {k.scopes.map((s) => (
                            <Tag key={s}>{s}</Tag>
                          ))}
                        </div>
                      )}
                    </Td>
                    <Td className="text-xs text-ink-muted">{k.user?.name ?? <Muted>—</Muted>}</Td>
                    <Td className="tabular text-xs text-ink-muted">
                      {k.lastUsedAt
                        ? k.lastUsedAt.toISOString().slice(0, 16).replace("T", " ")
                        : <Muted>never</Muted>}
                    </Td>
                    <Td>
                      {k.revoked ? (
                        <span className="text-xs text-danger">revoked</span>
                      ) : (
                        <span className="text-xs text-ok">active</span>
                      )}
                    </Td>
                    <Td>
                      {!k.revoked ? (
                        <form action={revokeApiKey}>
                          <input type="hidden" name="id" value={k.id} />
                          <button
                            type="submit"
                            className="rounded border border-line px-2 py-1 text-xs text-ink-muted hover:border-danger/40 hover:bg-danger/10 hover:text-danger"
                          >
                            Revoke
                          </button>
                        </form>
                      ) : null}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </div>
    </div>
  );
}
