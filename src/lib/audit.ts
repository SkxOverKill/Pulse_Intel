import "server-only";

import { headers } from "next/headers";
import type { AuditAction } from "@/generated/prisma/enums";
import { db } from "@/lib/db";

type AuditInput = {
  action: AuditAction;
  entityType: string;
  entityId?: string;
  userId?: string;
  changes?: unknown;
};

/// Best-effort client IP. Behind a reverse proxy the first X-Forwarded-For entry
/// is the client; direct connections fall back to X-Real-IP.
async function clientIp(): Promise<string | undefined> {
  const h = await headers();
  const fwd = h.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0]?.trim();
  return h.get("x-real-ip") ?? undefined;
}

/// Records a mutation. Never throws — an audit failure must not roll back or
/// break the user's action, but it must be visible in the server log.
export async function audit(input: AuditInput): Promise<void> {
  try {
    await db.auditLog.create({
      data: {
        action: input.action,
        entityType: input.entityType,
        entityId: input.entityId,
        userId: input.userId,
        changes: (input.changes ?? undefined) as never,
        ipAddress: await clientIp(),
      },
    });
  } catch (err) {
    console.error("[audit] failed to record entry", input, err);
  }
}

/// Shallow before/after diff, limited to keys that actually changed. Keeps the
/// audit log readable instead of dumping whole rows on every edit.
export function diff(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): Record<string, { from: unknown; to: unknown }> {
  const out: Record<string, { from: unknown; to: unknown }> = {};
  for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const a = before[key];
    const b = after[key];
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      out[key] = { from: a, to: b };
    }
  }
  return out;
}
