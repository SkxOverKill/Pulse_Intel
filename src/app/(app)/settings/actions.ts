"use server";

import { revalidatePath } from "next/cache";
import * as z from "zod";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";
import { ok, withAction, type ActionResult } from "@/lib/actions";
import { generateApiKey } from "@/lib/auth/apikey";
import { API_SCOPES } from "@/lib/api/scopes";
import {
  encryptSecret,
  loadCredentialCache,
  CREDENTIAL_PROVIDERS,
} from "@/lib/enrichment/secrets";

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

const SetCredentialSchema = z.object({
  provider: z.enum(CREDENTIAL_PROVIDERS),
  // No legitimate provider key in this catalogue is short; an 8-char floor
  // catches accidents (pasting the env var name instead of its value).
  value: z.string().min(8, { error: "Provider keys are usually longer than 8 characters." }).trim(),
});

/**
 * Stores (or rotates) a provider key. The raw key is never kept: it is
 * encrypted at rest with CREDENTIAL_ENC_KEY and the audit entry records only
 * that the credential changed — a rotated key is opaque by design, so there is
 * no before/after payload to diff.
 */
export async function setProviderCredential(
  _prev: ActionResult,
  formData: FormData,
): Promise<ActionResult> {
  return withAction(
    { role: "ADMIN", schema: SetCredentialSchema, formData },
    async (input, user) => {
      const encValue = encryptSecret(input.value);

      const existing = await db.providerCredential.findUnique({
        where: { provider: input.provider },
      });
      if (existing) {
        await db.providerCredential.update({
          where: { provider: input.provider },
          data: { encValue, setById: user.id },
        });
        await audit({
          action: "UPDATE",
          entityType: "ProviderCredential",
          entityId: input.provider,
          userId: user.id,
          changes: { provider: input.provider },
        });
      } else {
        await db.providerCredential.create({
          data: { provider: input.provider, encValue, setById: user.id },
        });
        await audit({
          action: "CREATE",
          entityType: "ProviderCredential",
          entityId: input.provider,
          userId: user.id,
          changes: { provider: input.provider },
        });
      }

      // Re-hydrate the process cache so the new key is live immediately —
      // clearing it would just fall back to env until the next page load.
      await loadCredentialCache();
      revalidatePath("/settings");
      return ok();
    },
  );
}

/** Forgets a provider key — the environment fallback then applies again. */
export async function clearProviderCredential(formData: FormData): Promise<void> {
  await withAction(
    { role: "ADMIN", schema: z.object({ provider: z.enum(CREDENTIAL_PROVIDERS) }), formData },
    async (input, user) => {
      await db.providerCredential.delete({ where: { provider: input.provider } });
      await loadCredentialCache();
      await audit({
        action: "DELETE",
        entityType: "ProviderCredential",
        entityId: input.provider,
        userId: user.id,
        changes: { provider: input.provider },
      });
      return ok();
    },
  );
  revalidatePath("/settings");
}
