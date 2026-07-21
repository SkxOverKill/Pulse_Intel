"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, withAction, type ActionResult } from "@/lib/actions";

const TYPES = ["RSS", "TAXII", "MISP", "CSV", "JSON", "TEXT", "MANUAL"] as const;
const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] as const;

const SourceSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(2, { error: "Name must be at least 2 characters." }).trim(),
  type: z.enum(TYPES).default("MANUAL"),
  url: z.url({ error: "Must be a valid URL." }).optional().or(z.literal("")),
  schedule: z.string().trim().optional(),
  enabled: z.coerce.boolean().default(true),
  defaultTlp: z.enum(TLPS).default("AMBER"),
  defaultConfidence: z.coerce.number().int().min(0).max(100).default(50),
  // Null means indicators from this source never expire — correct for file
  // hashes, wrong for IP addresses.
  decayHalfLifeDays: z.coerce.number().int().min(0).max(3650).optional(),
});

export async function saveSource(
  _prev: ActionResult<void>,
  formData: FormData,
): Promise<ActionResult<void>> {
  const result = await withAction(
    { role: "ADMIN", schema: SourceSchema, formData },
    async (input, user) => {
      const data = {
        name: input.name,
        type: input.type,
        url: input.url || null,
        schedule: input.schedule || null,
        enabled: input.enabled,
        defaultTlp: input.defaultTlp,
        defaultConfidence: input.defaultConfidence,
        decayHalfLifeDays: input.decayHalfLifeDays ? input.decayHalfLifeDays : null,
      };

      if (input.id) {
        const before = await db.source.findUnique({ where: { id: input.id } });
        if (!before) return fail("That source no longer exists.");
        const after = await db.source.update({ where: { id: input.id }, data });
        await audit({
          action: "UPDATE",
          entityType: "Source",
          entityId: after.id,
          userId: user.id,
          changes: diff(before, after),
        });
      } else {
        const created = await db.source.create({ data });
        await audit({
          action: "CREATE",
          entityType: "Source",
          entityId: created.id,
          userId: user.id,
          changes: { name: created.name, type: created.type },
        });
      }
      return ok();
    },
  );

  if (!result.ok) return result;
  revalidatePath("/feeds");
  redirect("/feeds");
}

export async function toggleSource(formData: FormData): Promise<void> {
  await withAction(
    {
      role: "ADMIN",
      schema: z.object({
        id: z.string().min(1),
        enabled: z.coerce.boolean().default(false),
      }),
      formData,
    },
    async (input, user) => {
      await db.source.update({
        where: { id: input.id },
        data: { enabled: input.enabled },
      });
      await audit({
        action: "UPDATE",
        entityType: "Source",
        entityId: input.id,
        userId: user.id,
        changes: { enabled: input.enabled },
      });
      return ok();
    },
  );
  revalidatePath("/feeds");
}
