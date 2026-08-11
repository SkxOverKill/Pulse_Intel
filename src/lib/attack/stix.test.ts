import { describe, expect, it } from "vitest";
import { attackId, parseBundle, type StixBundle, type StixObject } from "./stix";

/**
 * Hand-built fixtures rather than the real 50MB bundle: these encode the exact
 * v19.1 shapes verified against the live data (detection moved off the technique
 * object, explicit subtechnique-of relationships, multi-tactic techniques), and
 * keep the suite fast and offline.
 */

const TACTIC_EXEC: StixObject = {
  id: "x-mitre-tactic--exec",
  type: "x-mitre-tactic",
  name: "Execution",
  x_mitre_shortname: "execution",
  description: "Running malicious code.",
  external_references: [{ source_name: "mitre-attack", external_id: "TA0002" }],
};

const TACTIC_PERSIST: StixObject = {
  id: "x-mitre-tactic--persist",
  type: "x-mitre-tactic",
  name: "Persistence",
  x_mitre_shortname: "persistence",
  external_references: [{ source_name: "mitre-attack", external_id: "TA0003" }],
};

const MATRIX: StixObject = {
  id: "x-mitre-matrix--1",
  type: "x-mitre-matrix",
  // Deliberately not alphabetical: matrix order is meaningful.
  tactic_refs: [TACTIC_PERSIST.id, TACTIC_EXEC.id],
};

const COLLECTION: StixObject = {
  id: "x-mitre-collection--1",
  type: "x-mitre-collection",
  name: "Enterprise ATT&CK",
  x_mitre_version: "19.1",
};

const PARENT: StixObject = {
  id: "attack-pattern--parent",
  type: "attack-pattern",
  name: "Scheduled Task/Job",
  description: "Parent technique.",
  external_references: [{ source_name: "mitre-attack", external_id: "T1053" }],
  kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }],
  x_mitre_platforms: ["Windows", "Linux"],
  x_mitre_is_subtechnique: false,
};

const CHILD: StixObject = {
  id: "attack-pattern--child",
  type: "attack-pattern",
  name: "Scheduled Task",
  external_references: [{ source_name: "mitre-attack", external_id: "T1053.005" }],
  kill_chain_phases: [
    { kill_chain_name: "mitre-attack", phase_name: "execution" },
    { kill_chain_name: "mitre-attack", phase_name: "persistence" },
    // A non-ATT&CK kill chain that must be ignored.
    { kill_chain_name: "lockheed", phase_name: "exploitation" },
  ],
  x_mitre_platforms: ["Windows"],
  x_mitre_is_subtechnique: true,
};

const REVOKED: StixObject = {
  id: "attack-pattern--revoked",
  type: "attack-pattern",
  name: "Old Technique",
  revoked: true,
  external_references: [{ source_name: "mitre-attack", external_id: "T9999" }],
};

const DEPRECATED: StixObject = {
  id: "attack-pattern--deprecated",
  type: "attack-pattern",
  name: "Fading Technique",
  x_mitre_deprecated: true,
  external_references: [{ source_name: "mitre-attack", external_id: "T8888" }],
  kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }],
};

const ANALYTIC: StixObject = {
  id: "x-mitre-analytic--1",
  type: "x-mitre-analytic",
  name: "Analytic 0001",
  description: "Look for schtasks.exe spawning from an office process.",
  x_mitre_log_source_references: [
    { x_mitre_data_component_ref: "x-mitre-data-component--proc", name: "windows:security" },
  ],
};

const DATA_COMPONENT: StixObject = {
  id: "x-mitre-data-component--proc",
  type: "x-mitre-data-component",
  name: "Process Creation",
};

const STRATEGY: StixObject = {
  id: "x-mitre-detection-strategy--1",
  type: "x-mitre-detection-strategy",
  name: "Detection Strategy for Scheduled Task",
  x_mitre_analytic_refs: [ANALYTIC.id],
};

const GROUP: StixObject = {
  id: "intrusion-set--g1",
  type: "intrusion-set",
  name: "APT29",
  external_references: [{ source_name: "mitre-attack", external_id: "G0016" }],
};

const rel = (
  id: string,
  type: string,
  source: string,
  target: string,
): StixObject => ({
  id,
  type: "relationship",
  relationship_type: type,
  source_ref: source,
  target_ref: target,
});

const BUNDLE: StixBundle = {
  type: "bundle",
  objects: [
    COLLECTION,
    MATRIX,
    TACTIC_EXEC,
    TACTIC_PERSIST,
    PARENT,
    CHILD,
    REVOKED,
    DEPRECATED,
    ANALYTIC,
    DATA_COMPONENT,
    STRATEGY,
    GROUP,
    rel("rel--sub", "subtechnique-of", CHILD.id, PARENT.id),
    rel("rel--det", "detects", STRATEGY.id, CHILD.id),
    rel("rel--uses", "uses", GROUP.id, CHILD.id),
    // A `uses` pointing at malware, not a technique — must be ignored.
    rel("rel--uses2", "uses", GROUP.id, "malware--x"),
  ],
};

describe("attackId", () => {
  it("reads the mitre-attack external reference", () => {
    expect(attackId(PARENT)).toBe("T1053");
  });

  it("returns null when there is no ATT&CK reference", () => {
    expect(attackId({ id: "x", type: "attack-pattern" })).toBeNull();
  });
});

describe("parseBundle", () => {
  const parsed = parseBundle(BUNDLE);

  it("reads the collection version", () => {
    expect(parsed.version).toBe("19.1");
  });

  it("orders tactics by the matrix, not alphabetically", () => {
    expect(parsed.tactics.map((t) => t.shortname)).toEqual([
      "persistence",
      "execution",
    ]);
    expect(parsed.tactics[0].order).toBe(0);
    expect(parsed.tactics[1].order).toBe(1);
  });

  it("keeps every tactic a technique belongs to", () => {
    const child = parsed.techniques.find((t) => t.attackId === "T1053.005")!;
    expect(child.tactics).toEqual(["execution", "persistence"]);
  });

  it("ignores non-ATT&CK kill chains", () => {
    const child = parsed.techniques.find((t) => t.attackId === "T1053.005")!;
    expect(child.tactics).not.toContain("exploitation");
  });

  it("drops revoked techniques but keeps deprecated ones flagged", () => {
    const ids = parsed.techniques.map((t) => t.attackId);
    expect(ids).not.toContain("T9999");
    expect(ids).toContain("T8888");
    expect(parsed.techniques.find((t) => t.attackId === "T8888")!.deprecated).toBe(true);
  });

  it("resolves sub-technique parents from the relationship, not the id string", () => {
    const child = parsed.techniques.find((t) => t.attackId === "T1053.005")!;
    expect(child.isSubtechnique).toBe(true);
    expect(child.parentAttackId).toBe("T1053");

    const parent = parsed.techniques.find((t) => t.attackId === "T1053")!;
    expect(parent.parentAttackId).toBeNull();
  });

  it("composes detection prose from linked analytics", () => {
    const child = parsed.techniques.find((t) => t.attackId === "T1053.005")!;
    expect(child.detection).toContain("schtasks.exe");
  });

  it("resolves data sources from analytic log source references", () => {
    const child = parsed.techniques.find((t) => t.attackId === "T1053.005")!;
    expect(child.dataSources).toEqual(["Process Creation"]);
  });

  it("leaves detection null for techniques with no strategy", () => {
    const parent = parsed.techniques.find((t) => t.attackId === "T1053")!;
    expect(parent.detection).toBeNull();
    expect(parent.dataSources).toEqual([]);
  });

  it("extracts group to technique mappings", () => {
    expect(parsed.groupMappings).toEqual([
      { groupId: "G0016", groupName: "APT29", techniqueAttackId: "T1053.005" },
    ]);
  });

  it("ignores `uses` relationships that do not target a technique", () => {
    expect(parsed.groupMappings).toHaveLength(1);
  });

  it("merges every matrix, largest first", () => {
    // Mobile ships "Network-Based Effects" (2 tactics) *before* the real
    // "Mobile ATT&CK" (12). Reading only the first matrix drops 12 tactics and
    // orphans every technique in them.
    const legacy: StixObject = {
      id: "x-mitre-tactic--legacy",
      type: "x-mitre-tactic",
      name: "Network Effects",
      x_mitre_shortname: "network-effects",
      external_references: [{ source_name: "mitre-attack", external_id: "TA0038" }],
    };
    const bundle: StixBundle = {
      type: "bundle",
      objects: [
        COLLECTION,
        // Smaller legacy matrix deliberately listed first.
        { id: "m--legacy", type: "x-mitre-matrix", tactic_refs: [legacy.id] },
        {
          id: "m--primary",
          type: "x-mitre-matrix",
          tactic_refs: [TACTIC_PERSIST.id, TACTIC_EXEC.id],
        },
        legacy,
        TACTIC_EXEC,
        TACTIC_PERSIST,
      ],
    };
    const result = parseBundle(bundle);
    expect(result.tactics.map((t) => t.shortname)).toEqual([
      "persistence",
      "execution",
      "network-effects",
    ]);
    expect(result.tactics.map((t) => t.order)).toEqual([0, 1, 2]);
  });

  it("does not duplicate a tactic listed in two matrices", () => {
    const bundle: StixBundle = {
      type: "bundle",
      objects: [
        COLLECTION,
        { id: "m--a", type: "x-mitre-matrix", tactic_refs: [TACTIC_EXEC.id, TACTIC_PERSIST.id] },
        { id: "m--b", type: "x-mitre-matrix", tactic_refs: [TACTIC_EXEC.id] },
        TACTIC_EXEC,
        TACTIC_PERSIST,
      ],
    };
    const result = parseBundle(bundle);
    expect(result.tactics).toHaveLength(2);
  });

  it("handles an empty bundle without throwing", () => {
    const empty = parseBundle({ type: "bundle", objects: [] });
    expect(empty.techniques).toEqual([]);
    expect(empty.tactics).toEqual([]);
    expect(empty.groupMappings).toEqual([]);
  });
});
