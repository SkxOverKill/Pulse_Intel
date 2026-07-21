"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, parseList, withAction, type ActionResult } from "@/lib/actions";
import { slugify } from "@/lib/utils";

const STATUSES = ["SUSPECTED", "ACTIVE", "DORMANT", "CONCLUDED"] as const;
const TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] as const;

const CampaignSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(2, { error: "Name must be at least 2 characters." }).trim(),
  description: z.string().trim().optional(),
  status: z.enum(STATUSES).default("SUSPECTED"),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  targetSectors: z.string().optional(),
  targetCountries: z.string().optional(),
  tlp: z.enum(TLPS).default("AMBER"),
  confidence: z.coerce.number().int().min(0).max(100).default(50),
});

const toDate = (v?: string) => {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};

export async function saveCampaign(
  _prev: ActionResult<void>,
  formData: FormData,
): Promise<ActionResult<void>> {
  let redirectTo: string | null = null;

  const result = await withAction(
    { role: "ANALYST", schema: CampaignSchema, formData },
    async (input, user) => {
      const data = {
        name: input.name,
        slug: slugify(input.name),
        description: input.description || null,
        status: input.status,
        startDate: toDate(input.startDate),
        endDate: toDate(input.endDate),
        targetSectors: parseList(input.targetSectors),
        targetCountries: parseList(input.targetCountries),
        tlp: input.tlp,
        confidence: input.confidence,
      };

      if (input.id) {
        const before = await db.campaign.findUnique({ where: { id: input.id } });
        if (!before) return fail("That campaign no longer exists.");
        const after = await db.campaign.update({ where: { id: input.id }, data });
        await audit({
          action: "UPDATE",
          entityType: "Campaign",
          entityId: after.id,
          userId: user.id,
          changes: diff(before, after),
        });
        redirectTo = `/campaigns/${after.id}`;
      } else {
        const created = await db.campaign.create({ data });
        await audit({
          action: "CREATE",
          entityType: "Campaign",
          entityId: created.id,
          userId: user.id,
          changes: { name: created.name },
        });
        redirectTo = `/campaigns/${created.id}`;
      }
      return ok();
    },
  );

  if (!result.ok) return result;
  revalidatePath("/campaigns");
  redirect(redirectTo!);
}

/**
 * Attribution is a separate action from editing the campaign itself, because it
 * is a different kind of claim — "this campaign happened" versus "this actor did
 * it" — and carries its own confidence.
 */
export async function linkActor(formData: FormData): Promise<void> {
  const campaignId = String(formData.get("campaignId") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({
        campaignId: z.string().min(1),
        actorId: z.string().min(1, { error: "Pick an actor." }),
        confidence: z.coerce.number().int().min(0).max(100).default(50),
      }),
      formData,
    },
    async (input, user) => {
      await db.campaignActor.upsert({
        where: {
          campaignId_actorId: {
            campaignId: input.campaignId,
            actorId: input.actorId,
          },
        },
        update: { confidence: input.confidence, addedById: user.id },
        create: {
          campaignId: input.campaignId,
          actorId: input.actorId,
          confidence: input.confidence,
          addedById: user.id,
        },
      });
      await audit({
        action: "UPDATE",
        entityType: "Campaign",
        entityId: input.campaignId,
        userId: user.id,
        changes: { attributedTo: input.actorId, confidence: input.confidence },
      });
      return ok();
    },
  );
  revalidatePath(`/campaigns/${campaignId}`);
}

export async function unlinkActor(formData: FormData): Promise<void> {
  const campaignId = String(formData.get("campaignId") ?? "");
  await withAction(
    {
      role: "ANALYST",
      schema: z.object({
        campaignId: z.string().min(1),
        actorId: z.string().min(1),
      }),
      formData,
    },
    async (input, user) => {
      await db.campaignActor.deleteMany({
        where: { campaignId: input.campaignId, actorId: input.actorId },
      });
      await audit({
        action: "UPDATE",
        entityType: "Campaign",
        entityId: input.campaignId,
        userId: user.id,
        changes: { removedAttribution: input.actorId },
      });
      return ok();
    },
  );
  revalidatePath(`/campaigns/${campaignId}`);
}

export async function deleteCampaign(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const result = await withAction(
    { role: "ADMIN", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      const campaign = await db.campaign.findUnique({ where: { id: input.id } });
      if (!campaign) return fail("Already deleted.");
      await db.campaign.delete({ where: { id: input.id } });
      await audit({
        action: "DELETE",
        entityType: "Campaign",
        entityId: input.id,
        userId: user.id,
        changes: { name: campaign.name },
      });
      return ok();
    },
  );
  if (!result.ok) redirect(`/campaigns/${id}`);
  revalidatePath("/campaigns");
  redirect("/campaigns");
}
