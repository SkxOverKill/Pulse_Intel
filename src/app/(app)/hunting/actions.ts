"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit, diff } from "@/lib/audit";
import { fail, ok, withAction, type ActionResult } from "@/lib/actions";
import { describeHunt, validateHuntQuery } from "@/lib/hunting/schema";
import { runHunt } from "@/lib/hunting/run";

const HuntSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(2, { error: "Name must be at least 2 characters." }).trim(),
  description: z.string().trim().optional(),
  // The builder serializes the AST into this hidden field as JSON.
  query: z.string().min(1, { error: "Build at least one condition." }),
  schedule: z.string().trim().optional(),
  notifyOnHit: z.coerce.boolean().default(false),
});

export async function saveHunt(
  _prev: ActionResult<void>,
  formData: FormData,
): Promise<ActionResult<void>> {
  let newId: string | undefined;

  const result = await withAction(
    { role: "ANALYST", schema: HuntSchema, formData },
    async (input, user) => {
      // The query is user-authored JSON — validate it here, not just in the
      // browser, so a hand-crafted POST can't persist a query the engine will
      // choke on at run time.
      let parsedQuery: unknown;
      try {
        parsedQuery = JSON.parse(input.query);
      } catch {
        return fail("The query is not valid JSON.");
      }
      const validated = validateHuntQuery(parsedQuery);
      if (!validated.ok) {
        return fail(`Query is invalid: ${validated.errors.join("; ")}`);
      }

      const data = {
        name: input.name,
        description: input.description || null,
        query: validated.ast as unknown as object,
        schedule: input.schedule || null,
        notifyOnHit: input.notifyOnHit,
      };

      if (input.id) {
        const before = await db.huntQuery.findUnique({ where: { id: input.id } });
        if (!before) return fail("That hunt no longer exists.");
        const after = await db.huntQuery.update({
          where: { id: input.id },
          data,
        });
        await audit({
          action: "UPDATE",
          entityType: "HuntQuery",
          entityId: after.id,
          userId: user.id,
          changes: diff(before, after),
        });
      } else {
        const created = await db.huntQuery.create({
          data: { ...data, ownerId: user.id },
        });
        newId = created.id;
        await audit({
          action: "CREATE",
          entityType: "HuntQuery",
          entityId: created.id,
          userId: user.id,
          changes: { name: created.name, query: describeHunt(validated.ast) },
        });
      }
      return ok();
    },
  );

  if (!result.ok) return result;
  revalidatePath("/hunting");
  redirect(newId ? `/hunting/${newId}` : "/hunting");
}

export async function deleteHunt(formData: FormData): Promise<void> {
  await withAction(
    { role: "ANALYST", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      await db.huntQuery.delete({ where: { id: input.id } });
      await audit({
        action: "DELETE",
        entityType: "HuntQuery",
        entityId: input.id,
        userId: user.id,
      });
      return ok();
    },
  );
  revalidatePath("/hunting");
  redirect("/hunting");
}

/**
 * Runs a hunt synchronously and records the run. Hunts are single count/select
 * queries, so an analyst clicking "Run now" gets the result on the same request
 * rather than waiting on the queue — the queue path is for the scheduler.
 */
export async function runHuntNow(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  await withAction(
    { role: "ANALYST", schema: z.object({ id: z.string().min(1) }), formData },
    async (input, user) => {
      const result = await runHunt(input.id);
      if (!result.ok) return fail(result.error);
      await audit({
        action: "UPDATE",
        entityType: "HuntQuery",
        entityId: input.id,
        userId: user.id,
        changes: {
          ran: true,
          matches: result.matchCount,
          new: result.newCount,
        },
      });
      return ok();
    },
  );
  revalidatePath(`/hunting/${id}`);
  revalidatePath("/hunting");
}

export async function acknowledgeAlert(formData: FormData): Promise<void> {
  await withAction(
    { role: "ANALYST", schema: z.object({ id: z.string().min(1) }), formData },
    async (input) => {
      await db.huntAlert.update({
        where: { id: input.id },
        data: { acknowledged: true },
      });
      return ok();
    },
  );
  revalidatePath("/hunting");
}
