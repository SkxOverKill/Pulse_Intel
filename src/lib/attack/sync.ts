// Shared domain logic — see the note in src/lib/ioc/ingest.ts on why this is
// not marked `server-only` (the Phase 4/5 worker imports it from plain Node).
import { db } from "@/lib/db";
import {
  ATTACK_VERSION,
  DOMAIN_ENUM,
  bundleUrl,
  parseBundle,
  type AttackDomainKey,
  type ParsedBundle,
  type StixBundle,
} from "@/lib/attack/stix";

export type SyncReport = {
  domain: AttackDomainKey;
  version: string;
  tactics: number;
  techniquesCreated: number;
  techniquesUpdated: number;
  subtechniquesLinked: number;
  groupMappingsAvailable: number;
  groupMappingsApplied: number;
  softwareAvailable: number;
  softwareCreated: number;
  softwareUpdated: number;
  softwareMappingsAvailable: number;
  softwareMappingsApplied: number;
};

/**
 * Downloads and ingests one ATT&CK domain.
 *
 * The version is pinned by default. MITRE reshapes fields between releases —
 * v19 moved detection off the technique object entirely — so upgrading is an
 * explicit act, never something that happens because a sync ran on a Tuesday.
 */
export async function syncAttackDomain(
  domain: AttackDomainKey,
  opts: { version?: string; applyGroupMappings?: boolean; userId?: string } = {},
): Promise<SyncReport> {
  const version = opts.version ?? ATTACK_VERSION;

  const res = await fetch(bundleUrl(domain, version));
  if (!res.ok) {
    throw new Error(
      `Failed to fetch ATT&CK ${domain} v${version}: HTTP ${res.status}`,
    );
  }
  const bundle = (await res.json()) as StixBundle;
  const parsed = parseBundle(bundle);

  return ingestParsedBundle(domain, parsed, opts);
}

export async function ingestParsedBundle(
  domain: AttackDomainKey,
  parsed: ParsedBundle,
  opts: { applyGroupMappings?: boolean; userId?: string } = {},
): Promise<SyncReport> {
  const domainEnum = DOMAIN_ENUM[domain];

  // --- Tactics ------------------------------------------------------------
  for (const t of parsed.tactics) {
    await db.tactic.upsert({
      where: { shortname_domain: { shortname: t.shortname, domain: domainEnum } },
      update: {
        attackId: t.attackId,
        name: t.name,
        description: t.description,
        order: t.order,
        attackVersion: parsed.version,
      },
      create: {
        attackId: t.attackId,
        name: t.name,
        shortname: t.shortname,
        description: t.description,
        domain: domainEnum,
        order: t.order,
        attackVersion: parsed.version,
      },
    });
  }

  // --- Techniques ---------------------------------------------------------
  const existing = await db.technique.findMany({
    where: { domain: domainEnum },
    select: { id: true, attackId: true },
  });
  const existingByAttackId = new Map(existing.map((t) => [t.attackId, t.id]));

  let created = 0;
  let updated = 0;

  for (const t of parsed.techniques) {
    const data = {
      name: t.name,
      description: t.description,
      tactics: t.tactics,
      platforms: t.platforms,
      dataSources: t.dataSources,
      detection: t.detection,
      isSubtechnique: t.isSubtechnique,
      deprecated: t.deprecated,
      attackVersion: parsed.version,
    };

    if (existingByAttackId.has(t.attackId)) {
      await db.technique.update({
        where: { attackId_domain: { attackId: t.attackId, domain: domainEnum } },
        data,
      });
      updated++;
    } else {
      const row = await db.technique.create({
        data: { ...data, attackId: t.attackId, domain: domainEnum },
      });
      existingByAttackId.set(t.attackId, row.id);
      created++;
    }
  }

  // --- Sub-technique parents ---------------------------------------------
  // A second pass: parents must exist before children can point at them.
  let subtechniquesLinked = 0;
  for (const t of parsed.techniques) {
    if (!t.parentAttackId) continue;
    const parentId = existingByAttackId.get(t.parentAttackId);
    if (!parentId) continue;
    await db.technique.update({
      where: { attackId_domain: { attackId: t.attackId, domain: domainEnum } },
      data: { parentId },
    });
    subtechniquesLinked++;
  }

  // --- Group -> technique mappings ---------------------------------------
  let groupMappingsApplied = 0;

  if (opts.applyGroupMappings !== false) {
    // Only for actors we already track and have tied to an ATT&CK group id.
    // We never invent actors from MITRE data — which actors matter is the
    // analyst's call, not MITRE's.
    const actors = await db.threatActor.findMany({
      where: { attackGroupId: { not: null } },
      select: { id: true, attackGroupId: true },
    });
    const actorByGroup = new Map(
      actors.map((a) => [a.attackGroupId as string, a.id]),
    );

    if (actorByGroup.size > 0) {
      const rows: { actorId: string; techniqueId: string }[] = [];
      for (const m of parsed.groupMappings) {
        const actorId = actorByGroup.get(m.groupId);
        const techniqueId = existingByAttackId.get(m.techniqueAttackId);
        if (actorId && techniqueId) rows.push({ actorId, techniqueId });
      }

      if (rows.length) {
        const result = await db.actorTechnique.createMany({
          data: rows.map((r) => ({
            actorId: r.actorId,
            techniqueId: r.techniqueId,
            // MITRE's own attribution, recorded at high but not absolute
            // confidence, and with no addedById — it is not an analyst's claim.
            confidence: 75,
            notes: `Imported from MITRE ATT&CK v${parsed.version}`,
          })),
          skipDuplicates: true,
        });
        groupMappingsApplied = result.count;
      }
    }
  }

  // --- Software (malware + tools) ----------------------------------------
  // MITRE's `malware` and `tool` objects ingest into their own tables. We
  // never invent software either — what ships stays an analyst's call, but the
  // ATT&CK catalogue is the natural seed, identical to how techniques arrive.
  let softwareCreated = 0;
  let softwareUpdated = 0;

  for (const s of parsed.software) {
    if (s.kind === "malware") {
      const existing = await db.malware.findUnique({ where: { attackId: s.attackId } });
      if (existing) {
        await db.malware.update({ where: { attackId: s.attackId }, data: {
          name: s.name, aliases: s.aliases, platforms: s.platforms, description: s.description,
        } });
        softwareUpdated++;
      } else {
        await db.malware.create({ data: {
          name: s.name, aliases: s.aliases, platforms: s.platforms, description: s.description,
          attackId: s.attackId,
        } });
        softwareCreated++;
      }
    } else {
      const existing = await db.tool.findUnique({ where: { attackId: s.attackId } });
      if (existing) {
        await db.tool.update({ where: { attackId: s.attackId }, data: {
          name: s.name, aliases: s.aliases, description: s.description,
          // Tools in the ATT&CK catalogue are dual-use by MITRE's definition —
          // the `malware` objects carry the malicious half.
          dualUse: true,
        } });
        softwareUpdated++;
      } else {
        await db.tool.create({ data: {
          name: s.name, aliases: s.aliases, description: s.description,
          attackId: s.attackId, dualUse: true,
        } });
        softwareCreated++;
      }
    }
  }

  // --- Group -> software mappings ----------------------------------------
  // Same rule as techniques: only for actors we already track and have tied to
  // an ATT&CK group id, at MITRE's confidence, and never in an analyst's name.
  let softwareMappingsApplied = 0;

  if (opts.applyGroupMappings !== false && parsed.softwareMappings.length > 0) {
    const actors = await db.threatActor.findMany({
      where: { attackGroupId: { not: null } },
      select: { id: true, attackGroupId: true },
    });
    const actorByGroup = new Map(actors.map((a) => [a.attackGroupId as string, a.id]));
    if (actorByGroup.size > 0) {
      const [existingMalware, existingTools] = await Promise.all([
        db.malware.findMany({ select: { id: true, attackId: true } }),
        db.tool.findMany({ select: { id: true, attackId: true } }),
      ]);
      const malwareIdByAttack = new Map(existingMalware.map((m) => [m.attackId, m.id]));
      const toolIdByAttack = new Map(existingTools.map((t) => [t.attackId, t.id]));

      const malwareRows: { actorId: string; malwareId: string; confidence: number }[] = [];
      const toolRows: { actorId: string; toolId: string; confidence: number }[] = [];

      for (const m of parsed.softwareMappings) {
        const actorId = actorByGroup.get(m.groupId);
        if (!actorId) continue;
        if (m.kind === "malware") {
          const malwareId = malwareIdByAttack.get(m.softwareAttackId);
          if (malwareId) malwareRows.push({ actorId, malwareId, confidence: 75 });
        } else {
          const toolId = toolIdByAttack.get(m.softwareAttackId);
          if (toolId) toolRows.push({ actorId, toolId, confidence: 75 });
        }
      }

      if (malwareRows.length) {
        const result = await db.actorMalware.createMany({
          data: malwareRows, skipDuplicates: true,
        });
        softwareMappingsApplied += result.count;
      }
      if (toolRows.length) {
        const result = await db.actorTool.createMany({
          data: toolRows, skipDuplicates: true,
        });
        softwareMappingsApplied += result.count;
      }
    }
  }

  return {
    domain,
    version: parsed.version,
    tactics: parsed.tactics.length,
    techniquesCreated: created,
    techniquesUpdated: updated,
    subtechniquesLinked,
    groupMappingsAvailable: parsed.groupMappings.length,
    groupMappingsApplied,
    softwareAvailable: parsed.software.length,
    softwareCreated,
    softwareUpdated,
    softwareMappingsAvailable: parsed.softwareMappings.length,
    softwareMappingsApplied,
  };
}
