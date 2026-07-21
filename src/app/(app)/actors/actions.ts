"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, parseList, withAction, type ActionResult } from "@/lib/actions";
import { slugify } from "@/lib/utils";

const MOTIVATIONS = [
  "ESPIONAGE",
  "FINANCIAL",
  "HACKTIVISM",
  "DESTRUCTION",
  "INFORMATION_OPS",
  "UNKNOWN",
] as const;

const SOPHISTICATIONS = [
  "MINIMAL",
  "INTERMEDIATE",
  "ADVANCED",
  "EXPERT",
  "STRATEGIC",
] as const;

const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] as const;

const ActorSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(2, { error: "Name must be at least 2 characters." }).trim(),
  description: z.string().trim().optional(),
  attackGroupId: z
    .string()
    .trim()
    .regex(/^G\d{4}$/, { error: "ATT&CK group id looks like G0016." })
    .optional()
    .or(z.literal("")),
  country: z.string().trim().optional(),
  motivation: z.enum(MOTIVATIONS).default("UNKNOWN"),
  sophistication: z.enum(SOPHISTICATIONS).optional().or(z.literal("")),
  tlp: z.enum(TLPS).default("AMBER"),
  confidence: z.coerce.number().int().min(0).max(100).default(50),
  active: z.coerce.boolean().default(true),
  targetSectors: z.string().optional(),
  targetCountries: z.string().optional(),
  firstSeen: z.string().optional(),
  lastSeen: z.string().optional(),
});

function toDate(value?: string): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export async function saveActor(
  _prev: ActionResult<void>,
  formData: FormData,
): Promise<ActionResult<void>> {
  let redirectTo: string | null = null;

  const result = await withAction(
    { role: "ANALYST", schema: ActorSchema, formData },
    async (input, user) => {
      const data = {
        name: input.name,
        slug: slugify(input.name),
        description: input.description || null,
        attackGroupId: input.attackGroupId || null,
        country: input.country || null,
        motivation: input.motivation,
        sophistication: input.sophistication || null,
        tlp: input.tlp,
        confidence: input.confidence,
        active: input.active,
        targetSectors: parseList(input.targetSectors),
        targetCountries: parseList(input.targetCountries),
        firstSeen: toDate(input.firstSeen),
        lastSeen: toDate(input.lastSeen),
      };

      if (input.id) {
        const before = await db.threatActor.findUnique({ where: { id: input.id } });
        if (!before) return fail("That threat actor no longer exists.");

        const after = await db.threatActor.update({
          where: { id: input.id },
          data,
        });
        await audit({
          action: "UPDATE",
          entityType: "ThreatActor",
          entityId: after.id,
          userId: user.id,
          changes: diff(before, after),
        });
        redirectTo = `/actors/${after.id}`;
      } else {
        const created = await db.threatActor.create({ data });
        await audit({
          action: "CREATE",
          entityType: "ThreatActor",
          entityId: created.id,
          userId: user.id,
          changes: { name: created.name },
        });
        redirectTo = `/actors/${created.id}`;
      }

      return ok();
    },
  );

  if (!result.ok) return result;

  revalidatePath("/actors");
  // redirect() throws, so it must run outside the try/catch inside withAction —
  // otherwise the control-flow exception is swallowed as an unhandled error.
  redirect(redirectTo!);
}

export async function deleteActor(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const result = await withAction(
    { role: "ADMIN", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      const actor = await db.threatActor.findUnique({ where: { id: input.id } });
      if (!actor) return fail("Already deleted.");

      await db.threatActor.delete({ where: { id: input.id } });
      await audit({
        action: "DELETE",
        entityType: "ThreatActor",
        entityId: input.id,
        userId: user.id,
        changes: { name: actor.name },
      });
      return ok();
    },
  );

  if (!result.ok) {
    // Deletion is admin-only and initiated from a plain form; surfacing the
    // failure inline would need client state, so send them to the detail page
    // where the record is visibly still present.
    redirect(`/actors/${id}`);
  }

  revalidatePath("/actors");
  redirect("/actors");
}

const AliasSchema = z.object({
  actorId: z.string().min(1),
  alias: z.string().min(1, { error: "Alias cannot be empty." }).trim(),
  namedBy: z.string().trim().optional(),
});

export async function addAlias(formData: FormData): Promise<void> {
  const actorId = String(formData.get("actorId") ?? "");
  await withAction(
    { role: "ANALYST", schema: AliasSchema, formData },
    async (input, user) => {
      await db.actorAlias.create({
        data: {
          actorId: input.actorId,
          alias: input.alias,
          namedBy: input.namedBy || null,
          addedById: user.id,
        },
      });
      await audit({
        action: "UPDATE",
        entityType: "ThreatActor",
        entityId: input.actorId,
        userId: user.id,
        changes: { addedAlias: input.alias, namedBy: input.namedBy },
      });
      return ok();
    },
  );
  revalidatePath(`/actors/${actorId}`);
}

/**
 * Map an ATT&CK technique to an actor.
 *
 * Kept separate from editing the actor because it is a different claim with its
 * own confidence — and because an analyst overriding an imported MITRE mapping
 * needs their name on it. Upsert sets `addedById`, so a hand-reviewed mapping is
 * visibly distinguishable from the bulk MITRE import afterwards.
 */
export async function linkTechnique(formData: FormData): Promise<void> {
  const actorId = String(formData.get("actorId") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({
        actorId: z.string().min(1),
        techniqueId: z.string().min(1, { error: "Pick a technique." }),
        confidence: z.coerce.number().int().min(0).max(100).default(50),
        notes: z.string().trim().optional(),
      }),
      formData,
    },
    async (input, user) => {
      await db.actorTechnique.upsert({
        where: {
          actorId_techniqueId: {
            actorId: input.actorId,
            techniqueId: input.techniqueId,
          },
        },
        update: {
          confidence: input.confidence,
          notes: input.notes || null,
          addedById: user.id,
        },
        create: {
          actorId: input.actorId,
          techniqueId: input.techniqueId,
          confidence: input.confidence,
          notes: input.notes || null,
          addedById: user.id,
        },
      });
      await audit({
        action: "UPDATE",
        entityType: "ThreatActor",
        entityId: input.actorId,
        userId: user.id,
        changes: { linkedTechnique: input.techniqueId, confidence: input.confidence },
      });
      return ok();
    },
  );
  revalidatePath(`/actors/${actorId}`);
}

export async function unlinkTechnique(formData: FormData): Promise<void> {
  const actorId = String(formData.get("actorId") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({
        actorId: z.string().min(1),
        techniqueId: z.string().min(1),
      }),
      formData,
    },
    async (input, user) => {
      await db.actorTechnique.deleteMany({
        where: { actorId: input.actorId, techniqueId: input.techniqueId },
      });
      await audit({
        action: "UPDATE",
        entityType: "ThreatActor",
        entityId: input.actorId,
        userId: user.id,
        changes: { unlinkedTechnique: input.techniqueId },
      });
      return ok();
    },
  );
  revalidatePath(`/actors/${actorId}`);
}

export async function removeAlias(formData: FormData): Promise<void> {
  const actorId = String(formData.get("actorId") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({ id: z.string().min(1), actorId: z.string().min(1) }),
      formData,
    },
    async (input, user) => {
      const alias = await db.actorAlias.findUnique({ where: { id: input.id } });
      if (!alias) return fail("Already removed.");
      await db.actorAlias.delete({ where: { id: input.id } });
      await audit({
        action: "UPDATE",
        entityType: "ThreatActor",
        entityId: input.actorId,
        userId: user.id,
        changes: { removedAlias: alias.alias },
      });
      return ok();
    },
  );
  revalidatePath(`/actors/${actorId}`);
}
