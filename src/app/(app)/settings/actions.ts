"use server";

import { revalidatePath } from "next/cache";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { ok, withAction, type ActionResult } from "@/lib/actions";
import { generateApiKey } from "@/lib/auth/apikey";
import { API_SCOPES } from "@/lib/api/scopes";

const SCOPE_VALUES = API_SCOPES.map((s) => s.value) as [string, ...string[]];

const CreateKeySchema = z.object({
  name: z.string().min(2, { error: "Name must be at least 2 characters." }).trim(),
  // withAction only surfaces an array when 2+ values share a form field name
  // (see its raw-parsing comment) — a single checked checkbox arrives as a bare
  // string, so a single value must be normalized into a one-element array.
  scopes: z.preprocess(
    (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]),
    z.array(z.enum(SCOPE_VALUES)),
  ),
});

/**
 * Creates an API key and returns the raw secret exactly once — the caller must
 * show it immediately and never has another chance. Only `keyHash` (and the
 * display `prefix`) are persisted, mirroring session tokens (auth/session.ts).
 */
export async function createApiKey(
  _prev: ActionResult<{ raw: string }>,
  formData: FormData,
): Promise<ActionResult<{ raw: string }>> {
  return withAction(
    { role: "ADMIN", schema: CreateKeySchema, formData },
    async (input, user) => {
      const { raw, prefix, hash } = generateApiKey();

      const created = await db.apiKey.create({
        data: {
          name: input.name,
          keyHash: hash,
          prefix,
          userId: user.id,
          scopes: input.scopes,
        },
      });

      await audit({
        action: "CREATE",
        entityType: "ApiKey",
        entityId: created.id,
        userId: user.id,
        changes: { name: created.name, scopes: created.scopes },
      });

      revalidatePath("/settings");
      return ok({ raw });
    },
  );
}

export async function revokeApiKey(formData: FormData): Promise<void> {
  await withAction(
    { role: "ADMIN", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      await db.apiKey.update({ where: { id: input.id }, data: { revoked: true } });
      await audit({
        action: "UPDATE",
        entityType: "ApiKey",
        entityId: input.id,
        userId: user.id,
        changes: { revoked: true },
      });
      return ok();
    },
  );
  revalidatePath("/settings");
}
