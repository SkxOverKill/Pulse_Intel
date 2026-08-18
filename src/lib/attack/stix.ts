/**
 * MITRE ATT&CK STIX 2.1 parsing.
 *
 * Pure functions over a parsed bundle — no database, no network — so the shape
 * of MITRE's data is handled in one testable place.
 *
 * Verified against ATT&CK v19.1 (released 2026-05-12). Two things changed in
 * recent releases that older integrations get wrong:
 *
 *   - `x_mitre_detection` and `x_mitre_data_sources` no longer exist on
 *     attack-pattern objects. Zero of the 858 enterprise techniques carry them.
 *     Detection guidance now lives in `x-mitre-detection-strategy` objects
 *     linked by a `detects` relationship, which in turn reference
 *     `x-mitre-analytic` objects holding the actual prose and log sources.
 *   - Sub-technique parentage has an explicit `subtechnique-of` relationship;
 *     we use it rather than string-splitting "T1566.001".
 */

export const ATTACK_VERSION = "19.1";

export type AttackDomainKey = "enterprise" | "mobile" | "ics";

export const DOMAIN_ENUM = {
  enterprise: "ENTERPRISE",
  mobile: "MOBILE",
  ics: "ICS",
} as const;

export function bundleUrl(domain: AttackDomainKey, version = ATTACK_VERSION) {
  return `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/${domain}-attack/${domain}-attack-${version}.json`;
}

// --- Minimal STIX shapes (only the fields we consume) ---------------------

type ExternalRef = {
  source_name: string;
  external_id?: string;
  url?: string;
};

export type StixObject = {
  id: string;
  type: string;
  name?: string;
  description?: string;
  revoked?: boolean;
  external_references?: ExternalRef[];
  kill_chain_phases?: { kill_chain_name: string; phase_name: string }[];
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
  tactic_refs?: string[];
  x_mitre_is_subtechnique?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_platforms?: string[];
  x_mitre_shortname?: string;
  x_mitre_version?: string;
  x_mitre_analytic_refs?: string[];
  x_mitre_log_source_references?: {
    x_mitre_data_component_ref?: string;
    name?: string;
    channel?: string;
  }[];
  x_mitre_aliases?: string[];
};

export type StixBundle = { type: string; objects: StixObject[] };

/**
 * STIX source/kill-chain names for the supported ATT&CK domains. The mobile
 * and ICS bundles use their own names ("mitre-mobile-attack",
 * "mitre-ics-attack") instead of the enterprise "mitre-attack".
 */
const MITRE_SOURCE_NAMES = new Set(["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]);

export function attackId(o: StixObject): string | null {
  const ref = o.external_references?.find((r) => MITRE_SOURCE_NAMES.has(r.source_name));
  return ref?.external_id ?? null;
}

// --- Parsed output --------------------------------------------------------

export type ParsedTactic = {
  attackId: string;
  name: string;
  shortname: string;
  description: string | null;
  order: number;
};

export type ParsedTechnique = {
  attackId: string;
  name: string;
  description: string | null;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  detection: string | null;
  isSubtechnique: boolean;
  parentAttackId: string | null;
  deprecated: boolean;
};

export type ParsedGroupMapping = {
  /** ATT&CK group id, e.g. "G0016". */
  groupId: string;
  groupName: string;
  techniqueAttackId: string;
};

export type ParsedSoftware = {
  /** "malware" for STIX `malware` objects, "tool" for `tool` and `x-mitre-tool`. */
  kind: "malware" | "tool";
  /** ATT&CK software id, e.g. "S0154". */
  attackId: string;
  name: string;
  aliases: string[];
  platforms: string[];
  description: string | null;
};

export type ParsedGroupSoftwareMapping = {
  /** ATT&CK group id, e.g. "G0016". */
  groupId: string;
  softwareAttackId: string;
  kind: "malware" | "tool";
};

export type ParsedBundle = {
  version: string;
  tactics: ParsedTactic[];
  techniques: ParsedTechnique[];
  groupMappings: ParsedGroupMapping[];
  software: ParsedSoftware[];
  softwareMappings: ParsedGroupSoftwareMapping[];
};

export function parseBundle(bundle: StixBundle): ParsedBundle {
  const objects = bundle.objects;
  const byId = new Map(objects.map((o) => [o.id, o]));

  const collection = objects.find((o) => o.type === "x-mitre-collection");
  const version = collection?.x_mitre_version ?? ATTACK_VERSION;

  // --- Tactics, ordered by the matrix rather than alphabetically ----------
  //
  // A domain can ship more than one matrix: mobile has "Mobile ATT&CK" (12
  // tactics) *and* the legacy "Network-Based Effects" (2), with the legacy one
  // listed first. Taking only the first matrix silently drops 12 tactics, and
  // every technique in them then has no column to appear in.
  //
  // So: walk every matrix, largest first (the domain's primary matrix is the
  // biggest), and dedupe. A tactic seen in two matrices keeps its earliest
  // position.
  const matrices = objects
    .filter((o) => o.type === "x-mitre-matrix")
    .sort((a, b) => (b.tactic_refs?.length ?? 0) - (a.tactic_refs?.length ?? 0));

  const tactics: ParsedTactic[] = [];
  const seenTactics = new Set<string>();

  for (const matrix of matrices) {
    for (const ref of matrix.tactic_refs ?? []) {
      const t = byId.get(ref);
      const id = t && attackId(t);
      if (!t || !id || !t.x_mitre_shortname) continue;
      if (seenTactics.has(t.x_mitre_shortname)) continue;
      seenTactics.add(t.x_mitre_shortname);
      tactics.push({
        attackId: id,
        name: t.name ?? t.x_mitre_shortname,
        shortname: t.x_mitre_shortname,
        description: t.description ?? null,
        order: tactics.length,
      });
    }
  }

  // --- Detection: strategy -> analytics -> prose + log sources ------------
  // Built as a lookup keyed by technique STIX id before walking techniques.
  const detectionByTechnique = new Map<string, { prose: string[]; sources: Set<string> }>();

  for (const rel of objects) {
    if (rel.type !== "relationship" || rel.relationship_type !== "detects") continue;
    const strategy = rel.source_ref ? byId.get(rel.source_ref) : undefined;
    const target = rel.target_ref;
    if (!strategy || !target) continue;
    if (strategy.type !== "x-mitre-detection-strategy") continue;
    if (strategy.x_mitre_deprecated || strategy.revoked) continue;

    const entry = detectionByTechnique.get(target) ?? {
      prose: [],
      sources: new Set<string>(),
    };

    for (const analyticRef of strategy.x_mitre_analytic_refs ?? []) {
      const analytic = byId.get(analyticRef);
      if (!analytic || analytic.x_mitre_deprecated) continue;
      if (analytic.description) entry.prose.push(analytic.description.trim());
      for (const ls of analytic.x_mitre_log_source_references ?? []) {
        const dc = ls.x_mitre_data_component_ref
          ? byId.get(ls.x_mitre_data_component_ref)
          : undefined;
        if (dc?.name) entry.sources.add(dc.name);
      }
    }
    detectionByTechnique.set(target, entry);
  }

  // --- Sub-technique parentage from the explicit relationship -------------
  const parentByChild = new Map<string, string>();
  for (const rel of objects) {
    if (rel.type !== "relationship" || rel.relationship_type !== "subtechnique-of") continue;
    if (!rel.source_ref || !rel.target_ref) continue;
    const parent = byId.get(rel.target_ref);
    const parentId = parent && attackId(parent);
    if (parentId) parentByChild.set(rel.source_ref, parentId);
  }

  // --- Techniques ---------------------------------------------------------
  const techniques: ParsedTechnique[] = [];

  for (const o of objects) {
    if (o.type !== "attack-pattern") continue;
    // Revoked means "replaced by another technique" — carrying it forward would
    // produce duplicate mappings for the same behaviour. Deprecated techniques
    // are kept but flagged, since historical mappings may still reference them.
    if (o.revoked) continue;
    const id = attackId(o);
    if (!id) continue;

    const det = detectionByTechnique.get(o.id);

    techniques.push({
      attackId: id,
      name: o.name ?? id,
      description: o.description ?? null,
      tactics: (o.kill_chain_phases ?? [])
        .filter((k) => MITRE_SOURCE_NAMES.has(k.kill_chain_name))
        .map((k) => k.phase_name),
      platforms: o.x_mitre_platforms ?? [],
      dataSources: det ? [...det.sources].sort() : [],
      detection: det && det.prose.length ? det.prose.join("\n\n") : null,
      isSubtechnique: Boolean(o.x_mitre_is_subtechnique),
      parentAttackId: parentByChild.get(o.id) ?? null,
      deprecated: Boolean(o.x_mitre_deprecated),
    });
  }

  // --- Group -> technique mappings ---------------------------------------
  // MITRE's own attribution, used as a starting point for actor TTP profiles.
  const groupMappings: ParsedGroupMapping[] = [];

  for (const rel of objects) {
    if (rel.type !== "relationship" || rel.relationship_type !== "uses") continue;
    if (!rel.source_ref || !rel.target_ref) continue;
    const group = byId.get(rel.source_ref);
    const technique = byId.get(rel.target_ref);
    if (group?.type !== "intrusion-set" || technique?.type !== "attack-pattern") continue;
    if (group.revoked || technique.revoked) continue;

    const groupId = attackId(group);
    const techniqueAttackId = attackId(technique);
    if (!groupId || !techniqueAttackId) continue;

    groupMappings.push({
      groupId,
      groupName: group.name ?? groupId,
      techniqueAttackId,
    });
  }

  // --- Software -----------------------------------------------------------
  // ATT&CK's `malware` and `tool` objects. `x-mitre-tool` still appears in the
  // archives of older releases; treat it as a tool so those bundles re-sync.
  const softwareIdToKind = new Map<string, "malware" | "tool">();
  const software: ParsedSoftware[] = [];

  for (const o of objects) {
    const kind: "malware" | "tool" | null =
      o.type === "malware" ? "malware"
      : o.type === "tool" || o.type === "x-mitre-tool" ? "tool"
      : null;
    if (!kind) continue;
    if (o.revoked) continue; // Replaced object — carrying it forward is stale.
    const id = attackId(o);
    if (!id) continue;

    softwareIdToKind.set(o.id, kind);
    software.push({
      kind,
      attackId: id,
      name: o.name ?? id,
      aliases: o.x_mitre_aliases ?? [],
      platforms: o.x_mitre_platforms ?? [],
      description: o.description ?? null,
    });
  }

  // --- Group -> software mappings ----------------------------------------
  // Same `uses` relationship, but the target is software rather than a
  // technique. Kept apart from groupMappings because the two ingest into
  // different tables downstream.
  const softwareMappings: ParsedGroupSoftwareMapping[] = [];

  for (const rel of objects) {
    if (rel.type !== "relationship" || rel.relationship_type !== "uses") continue;
    if (!rel.source_ref || !rel.target_ref) continue;
    const group = byId.get(rel.source_ref);
    if (group?.type !== "intrusion-set" || group.revoked) continue;

    const groupId = attackId(group);
    const kind = softwareIdToKind.get(rel.target_ref);
    if (!groupId || !kind) continue;

    const target = byId.get(rel.target_ref);
    const softwareAttackId = target && attackId(target);
    if (!softwareAttackId) continue;

    softwareMappings.push({ groupId, softwareAttackId, kind });
  }

  return { version, tactics, techniques, groupMappings, software, softwareMappings };
}
