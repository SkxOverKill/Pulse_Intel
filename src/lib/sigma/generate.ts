/**
 * Sigma rule generator — produce ready-to-use detection rules from actor or
 * campaign data stored in Pulse Intelligence.
 *
 * Sigma is the de-facto standard for vendor-agnostic detection rules. A rule
 * generated here can be dropped straight into sigma-cli and compiled to
 * Splunk SPL, Elastic EQL, QRadar AQL, Microsoft Sentinel KQL, or Chronicle
 * YARA-L. That single-step integration is why SOC analysts care about this.
 *
 * The generator focuses on three rule categories:
 *
 *   1. Network IOC rules — IP/domain/URL blocklist rules for network detection.
 *      These go into firewall enrichment, proxy logs, DNS logs.
 *
 *   2. Process / command-line rules — built from technique-to-detection
 *      mappings. For techniques with known command patterns (T1059, T1053,
 *      T1086, etc.) we emit concrete `CommandLine|contains` conditions.
 *
 *   3. File hash rules — SHA256/MD5 file indicator rules for EDR detection.
 *
 * Technique-to-detection mapping lives in TECHNIQUE_DETECTIONS below. It is
 * deliberately conservative — only techniques where we can generate a rule
 * that has a real true-positive rate. Vague techniques (T1566 Phishing) are
 * skipped; overly-broad rules flood SIEMs and analysts stop trusting them.
 */

import { randomUUID } from "crypto";

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

export type SigmaRule = {
  title: string;
  id: string;
  status: "experimental" | "test" | "stable";
  description: string;
  author: string;
  date: string;
  tags: string[];
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    selection: Record<string, unknown>;
    condition: string;
  };
  falsepositives: string[];
  level: "informational" | "low" | "medium" | "high" | "critical";
};

export type GenerateOptions = {
  /** Actor or campaign name — used in rule titles and author field. */
  actorName: string;
  /** ATT&CK group ID if available, e.g. "G0016". */
  attackGroupId?: string | null;
  /** Linked technique ATT&CK IDs with confidence, e.g. [{ attackId: "T1059.001", confidence: 80 }] */
  techniques: Array<{ attackId: string; name: string; confidence: number }>;
  /** Network indicators (IP, domain, URL) linked to the actor/campaign. */
  networkIndicators: Array<{ type: string; normalizedValue: string; confidence: number }>;
  /** File hash indicators linked to the actor/campaign. */
  hashIndicators: Array<{ type: string; normalizedValue: string; confidence: number }>;
  /** Registry/mutex/filename indicators. */
  hostIndicators: Array<{ type: string; normalizedValue: string; confidence: number }>;
};

// --------------------------------------------------------------------------
// Technique-to-detection mapping
// --------------------------------------------------------------------------

type TechniqueDetection = {
  logsource: SigmaRule["logsource"];
  /** Returns null when we cannot generate a useful rule for this technique. */
  build: (
    actorName: string,
    techniqueId: string,
    techniqueName: string,
    confidence: number,
  ) => SigmaRule | null;
};

const ISO_DATE = new Date().toISOString().slice(0, 10);

function base(
  title: string,
  description: string,
  tags: string[],
  level: SigmaRule["level"],
  actorName: string,
): Omit<SigmaRule, "logsource" | "detection"> {
  return {
    title,
    id: randomUUID(),
    status: "experimental",
    description,
    author: `Pulse Intelligence — auto-generated for ${actorName}`,
    date: ISO_DATE,
    tags,
    falsepositives: ["Legitimate administrative activity — validate against known-good baselines."],
    level,
  };
}

/** Map ATT&CK technique IDs to concrete Sigma detection logic. */
const TECHNIQUE_DETECTIONS: Record<string, TechniqueDetection> = {
  // PowerShell execution
  "T1059.001": {
    logsource: { category: "process_creation", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — PowerShell Suspicious Execution (${tid})`,
        `Detects suspicious PowerShell invocation patterns associated with ${actor}. Technique: ${tname}.`,
        [`attack.execution`, `attack.t1059.001`],
        confidence >= 80 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "process_creation", product: "windows" },
      detection: {
        selection: {
          "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
          "CommandLine|contains|all": ["-EncodedCommand", "-NonInteractive"],
        },
        condition: "selection",
      },
    }),
  },
  // Windows Command Shell
  "T1059.003": {
    logsource: { category: "process_creation", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — Suspicious cmd.exe Execution (${tid})`,
        `Detects suspicious cmd.exe invocation patterns associated with ${actor}. Technique: ${tname}.`,
        [`attack.execution`, `attack.t1059.003`],
        confidence >= 80 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "process_creation", product: "windows" },
      detection: {
        selection: {
          "Image|endswith": "\\cmd.exe",
          "CommandLine|contains": ["/c ", "whoami", "net user", "ipconfig /all"],
        },
        condition: "selection",
      },
    }),
  },
  // Scheduled Task creation
  "T1053.005": {
    logsource: { category: "process_creation", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — Scheduled Task Creation (${tid})`,
        `Detects scheduled task creation linked to ${actor} persistence. Technique: ${tname}.`,
        [`attack.persistence`, `attack.privilege_escalation`, `attack.t1053.005`],
        confidence >= 70 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "process_creation", product: "windows" },
      detection: {
        selection: {
          "Image|endswith": "\\schtasks.exe",
          "CommandLine|contains": "/create",
        },
        condition: "selection",
      },
    }),
  },
  // Registry Run Key persistence
  "T1547.001": {
    logsource: { category: "registry_set", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — Registry Run Key Persistence (${tid})`,
        `Detects Run/RunOnce key modifications associated with ${actor}. Technique: ${tname}.`,
        [`attack.persistence`, `attack.t1547.001`],
        confidence >= 70 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "registry_set", product: "windows" },
      detection: {
        selection: {
          "TargetObject|contains": [
            "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          ],
        },
        condition: "selection",
      },
    }),
  },
  // LSASS credential dumping
  "T1003.001": {
    logsource: { category: "process_access", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — LSASS Memory Access / Credential Dumping (${tid})`,
        `Detects LSASS process access attributed to ${actor} credential harvesting. Technique: ${tname}.`,
        [`attack.credential_access`, `attack.t1003.001`],
        "critical",
        actor,
      ),
      logsource: { category: "process_access", product: "windows" },
      detection: {
        selection: {
          "TargetImage|endswith": "\\lsass.exe",
          "GrantedAccess|contains": ["0x1010", "0x1038", "0x40", "0x1FFFFF"],
        },
        filter_legit: {
          "SourceImage|contains": [
            "\\MsMpEng.exe",
            "\\WerFault.exe",
            "\\WerFaultSecure.exe",
          ],
        },
        condition: "selection and not filter_legit",
      },
    }),
  },
  // Remote services / lateral movement
  "T1021.002": {
    logsource: { category: "network_connection", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — SMB Lateral Movement (${tid})`,
        `Detects SMB connections matching ${actor} lateral movement patterns. Technique: ${tname}.`,
        [`attack.lateral_movement`, `attack.t1021.002`],
        confidence >= 70 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "network_connection", product: "windows" },
      detection: {
        selection: {
          "DestinationPort": 445,
          "Initiated": true,
        },
        condition: "selection",
      },
    }),
  },
  // Web shell
  "T1505.003": {
    // Matches what build() emits below — a webserver-category logsource here
    // would be dead config that silently disagrees with the generated rule.
    logsource: { category: "file_event", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — Web Shell Activity (${tid})`,
        `Detects web shell file creation or execution patterns linked to ${actor}. Technique: ${tname}.`,
        [`attack.persistence`, `attack.t1505.003`],
        "critical",
        actor,
      ),
      logsource: { category: "file_event", product: "windows" },
      detection: {
        selection: {
          "TargetFilename|endswith": [".aspx", ".ashx", ".asp", ".php", ".jsp"],
          "Image|endswith": ["\\w3wp.exe", "\\httpd.exe", "\\nginx.exe"],
        },
        condition: "selection",
      },
    }),
  },
  // BITSAdmin data exfil
  "T1197": {
    logsource: { category: "process_creation", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — BITS Transfer Abuse (${tid})`,
        `Detects BITSAdmin abuse for persistence or exfiltration by ${actor}. Technique: ${tname}.`,
        [`attack.defense_evasion`, `attack.persistence`, `attack.t1197`],
        confidence >= 70 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "process_creation", product: "windows" },
      detection: {
        selection: {
          "Image|endswith": "\\bitsadmin.exe",
          "CommandLine|contains": ["/transfer", "/addfile"],
        },
        condition: "selection",
      },
    }),
  },
  // Masquerading
  "T1036.005": {
    logsource: { category: "process_creation", product: "windows" },
    build: (actor, tid, tname, confidence) => ({
      ...base(
        `${actor} — Process Name Masquerading (${tid})`,
        `Detects processes impersonating legitimate system executables linked to ${actor}. Technique: ${tname}.`,
        [`attack.defense_evasion`, `attack.t1036.005`],
        confidence >= 70 ? "high" : "medium",
        actor,
      ),
      logsource: { category: "process_creation", product: "windows" },
      detection: {
        selection: {
          "Image|endswith": ["\\svchost.exe", "\\lsass.exe", "\\csrss.exe"],
        },
        filter_legit: {
          "Image|startswith": "C:\\Windows\\System32\\",
        },
        condition: "selection and not filter_legit",
      },
    }),
  },
};

// --------------------------------------------------------------------------
// Generator
// --------------------------------------------------------------------------

function generateNetworkRule(opts: GenerateOptions): SigmaRule | null {
  const ips     = opts.networkIndicators.filter((i) => i.type === "IPV4" || i.type === "IPV6");
  const domains = opts.networkIndicators.filter((i) => i.type === "DOMAIN");
  const urls    = opts.networkIndicators.filter((i) => i.type === "URL");

  if (ips.length === 0 && domains.length === 0 && urls.length === 0) return null;

  const tags = [`attack.command_and_control`];
  if (opts.attackGroupId) tags.push(`attack.group.${opts.attackGroupId.toLowerCase()}`);

  // Named sub-selections, one per observable type: within a single Sigma
  // selection map every field must match (AND), so a flat `selection` would
  // make a blocklist rule fire only when a single event contains a matching
  // domain AND IP AND URL at once. Splitting into `selection_*` keys makes
  // `1 of selection*` behave as an OR across observable types, which is what
  // an IOC blocklist means.
  const selection: Record<string, unknown> = {};
  if (domains.length > 0) {
    selection.selection_dns = {
      "dns.question.name|contains": domains.map((d) => d.normalizedValue),
    };
  }
  if (ips.length > 0) {
    selection.selection_ip = {
      DestinationIp: ips.map((i) => i.normalizedValue),
    };
  }
  if (urls.length > 0) {
    selection.selection_url = {
      "http.request.uri|contains": urls.map((u) => u.normalizedValue),
    };
  }

  return {
    ...base(
      `${opts.actorName} — Network IOC Detection`,
      `Matches network traffic to infrastructure attributed to ${opts.actorName}. Contains ${ips.length} IPs, ${domains.length} domains, ${urls.length} URLs.`,
      tags,
      "high",
      opts.actorName,
    ),
    logsource: { category: "network_connection" },
    detection: {
      selection,
      condition: "1 of selection*",
    },
  };
}

function generateHashRule(opts: GenerateOptions): SigmaRule | null {
  const sha256 = opts.hashIndicators.filter((i) => i.type === "SHA256");
  const md5    = opts.hashIndicators.filter((i) => i.type === "MD5");
  const sha1   = opts.hashIndicators.filter((i) => i.type === "SHA1");

  if (sha256.length === 0 && md5.length === 0 && sha1.length === 0) return null;

  const tags = [`attack.execution`];
  if (opts.attackGroupId) tags.push(`attack.group.${opts.attackGroupId.toLowerCase()}`);

  // Same pattern as the network rule: a flat selection would AND the hash
  // types together, so each type gets its own `selection_*` key and the
  // condition ORs them. All three match against Sysmon's `Hashes` field
  // (`MD5=..,SHA1=..,SHA256=..`) — `md5`/`sha1` are not standard Sigma fields,
  // so rules using them would silently never match in most backends.
  const selection: Record<string, unknown> = {};
  if (sha256.length > 0) {
    selection.selection_sha256 = {
      "Hashes|contains": sha256.map((h) => `SHA256=${h.normalizedValue.toUpperCase()}`),
    };
  }
  if (md5.length > 0) {
    selection.selection_md5 = {
      "Hashes|contains": md5.map((h) => `MD5=${h.normalizedValue.toUpperCase()}`),
    };
  }
  if (sha1.length > 0) {
    selection.selection_sha1 = {
      "Hashes|contains": sha1.map((h) => `SHA1=${h.normalizedValue.toUpperCase()}`),
    };
  }

  return {
    ...base(
      `${opts.actorName} — Malware File Hash Detection`,
      `Detects execution of files with hashes attributed to ${opts.actorName} malware. Contains ${sha256.length} SHA256, ${md5.length} MD5, ${sha1.length} SHA1 hashes.`,
      tags,
      "critical",
      opts.actorName,
    ),
    logsource: { category: "process_creation", product: "windows" },
    detection: {
      selection,
      condition: "1 of selection*",
    },
  };
}

function generateHostRule(opts: GenerateOptions): SigmaRule | null {
  const mutexes   = opts.hostIndicators.filter((i) => i.type === "MUTEX");
  const filenames = opts.hostIndicators.filter((i) => i.type === "FILENAME");
  const regkeys   = opts.hostIndicators.filter((i) => i.type === "REGISTRY_KEY");

  if (mutexes.length === 0 && filenames.length === 0 && regkeys.length === 0) return null;

  // Named sub-selections, same OR-across-types pattern as the network rule.
  const selection: Record<string, unknown> = {};
  if (mutexes.length > 0) {
    selection.selection_mutex = { ObjectName: mutexes.map((m) => m.normalizedValue) };
  }
  if (filenames.length > 0) {
    selection.selection_filename = {
      "TargetFilename|endswith": filenames.map((f) => f.normalizedValue),
    };
  }
  if (regkeys.length > 0) {
    selection.selection_regkey = {
      "TargetObject|contains": regkeys.map((r) => r.normalizedValue),
    };
  }

  return {
    ...base(
      `${opts.actorName} — Host Artifact Detection`,
      `Detects host-based artifacts (mutexes, files, registry keys) attributed to ${opts.actorName}.`,
      [`attack.defense_evasion`],
      "high",
      opts.actorName,
    ),
    logsource: { product: "windows" },
    detection: {
      selection,
      condition: "1 of selection*",
    },
  };
}

/** Generate all applicable Sigma rules for an actor or campaign. */
export function generateSigmaRules(opts: GenerateOptions): SigmaRule[] {
  const rules: SigmaRule[] = [];

  // 1. Network IOC rule
  const netRule = generateNetworkRule(opts);
  if (netRule) rules.push(netRule);

  // 2. File hash rule
  const hashRule = generateHashRule(opts);
  if (hashRule) rules.push(hashRule);

  // 3. Host artifact rule
  const hostRule = generateHostRule(opts);
  if (hostRule) rules.push(hostRule);

  // 4. Technique-based rules (only for mappings we have concrete logic for)
  for (const tech of opts.techniques) {
    const mapping = TECHNIQUE_DETECTIONS[tech.attackId];
    if (!mapping) continue;
    const rule = mapping.build(
      opts.actorName,
      tech.attackId,
      tech.name,
      tech.confidence,
    );
    if (rule) rules.push(rule);
  }

  return rules;
}

// --------------------------------------------------------------------------
// YAML serializer — keeps sigma-cli compatibility without a dep
// --------------------------------------------------------------------------

function yamlValue(v: unknown, indent = 0): string {
  const pad = " ".repeat(indent);
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return String(v);
  if (typeof v === "number") return String(v);
  if (typeof v === "string") {
    // Quote strings that would confuse YAML parsers
    if (
      v.includes(":") || v.includes("#") || v.includes("'") ||
      v.startsWith("{") || v.startsWith("[") || v === ""
    ) {
      return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    }
    return v;
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    return "\n" + v.map((item) => `${pad}  - ${yamlValue(item)}`).join("\n");
  }
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    if (entries.length === 0) return "{}";
    return "\n" + entries
      .map(([k, val]) => {
        const rendered = yamlValue(val, indent + 2);
        if (rendered.startsWith("\n")) {
          return `${pad}  ${k}:${rendered}`;
        }
        return `${pad}  ${k}: ${rendered}`;
      })
      .join("\n");
  }
  return String(v);
}

export function ruleToYaml(rule: SigmaRule): string {
  const fields: Array<[string, unknown]> = [
    ["title",         rule.title],
    ["id",            rule.id],
    ["status",        rule.status],
    ["description",   rule.description],
    ["author",        rule.author],
    ["date",          rule.date],
    ["tags",          rule.tags],
    ["logsource",     rule.logsource],
    ["detection",     rule.detection],
    ["falsepositives", rule.falsepositives],
    ["level",         rule.level],
  ];

  return fields
    .map(([k, v]) => {
      const rendered = yamlValue(v);
      if (rendered.startsWith("\n")) return `${k}:${rendered}`;
      return `${k}: ${rendered}`;
    })
    .join("\n") + "\n";
}

/** Produce a single .yml string containing all rules separated by --- */
export function rulesToYamlBundle(rules: SigmaRule[]): string {
  if (rules.length === 0) return "# No rules generated — no indicators or technique mappings found.\n";
  return rules.map(ruleToYaml).join("\n---\n\n");
}
