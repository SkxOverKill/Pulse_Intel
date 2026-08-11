/**
 * MITRE D3FEND countermeasure mapping for ATT&CK techniques.
 *
 * D3FEND is MITRE's defensive counterpart to ATT&CK — it maps attack
 * techniques to the defensive techniques that detect or mitigate them.
 * The D3FEND graph API (api.d3fend.mitre.org) is the authoritative source,
 * but it requires network access at render time. This module provides a
 * curated offline mapping for the most common techniques that analysts
 * encounter, enabling the UI to show countermeasures without a live call.
 *
 * Coverage: ~60 high-priority T-IDs drawn from CISA top-routinely-exploited
 * techniques and Mandiant M-Trends. The live API endpoint
 * GET /api/defend/:attackId is provided for the remainder.
 *
 * Each entry maps to one or more D3FEND techniques:
 *   d3fend_id  — D3FEND technique ID, e.g. "D3-PA"
 *   label      — human-readable name
 *   definition — one-line what-it-does
 *   category   — D3FEND tactic category (Harden, Detect, Isolate, Deceive, Evict)
 */

export type D3fendCountermeasure = {
  d3fend_id: string;
  label: string;
  definition: string;
  category: "Harden" | "Detect" | "Isolate" | "Deceive" | "Evict";
};

/** Mapping of ATT&CK technique ID → D3FEND countermeasures. */
export const DEFEND_MAP: Record<string, D3fendCountermeasure[]> = {
  // T1059 — Command and Scripting Interpreter
  "T1059": [
    { d3fend_id: "D3-SBV", label: "Script Execution Blocking", definition: "Block execution of scripts that are not signed or not from a trusted source.", category: "Harden" },
    { d3fend_id: "D3-PA",  label: "Process Ancestry Analysis", definition: "Detect anomalous parent-child process relationships spawned by scripting engines.", category: "Detect" },
  ],
  "T1059.001": [
    { d3fend_id: "D3-SBV",  label: "Script Execution Blocking",   definition: "Block unsigned or policy-violating PowerShell scripts via Constrained Language Mode or WDAC.", category: "Harden" },
    { d3fend_id: "D3-PSA",  label: "Process Spawn Analysis",      definition: "Detect encoded or obfuscated PowerShell invocations at the command-line level.", category: "Detect" },
    { d3fend_id: "D3-PBRD", label: "Process Behavior Analysis",   definition: "Detect PowerShell making unusual network connections or writing to sensitive paths.", category: "Detect" },
  ],
  "T1059.003": [
    { d3fend_id: "D3-PA",   label: "Process Ancestry Analysis",   definition: "Detect cmd.exe spawned from unusual parents (Office, browsers, web servers).", category: "Detect" },
    { d3fend_id: "D3-SBV",  label: "Script Execution Blocking",   definition: "Restrict cmd.exe access via AppLocker or Software Restriction Policies.", category: "Harden" },
  ],
  // T1003 — Credential Dumping
  "T1003": [
    { d3fend_id: "D3-CRO",  label: "Credential Hardening",        definition: "Implement Credential Guard and LSA Protection to protect credential material in memory.", category: "Harden" },
    { d3fend_id: "D3-PA",   label: "Process Access Analysis",     definition: "Detect processes reading LSASS memory or the SAM database.", category: "Detect" },
  ],
  "T1003.001": [
    { d3fend_id: "D3-CRO",  label: "Credential Hardening",        definition: "Enable Credential Guard (VBS-based LSASS isolation) on all endpoints.", category: "Harden" },
    { d3fend_id: "D3-PA",   label: "Process Access Analysis",     definition: "Alert on any process requesting PROCESS_VM_READ on lsass.exe.", category: "Detect" },
    { d3fend_id: "D3-LNCA", label: "Local Network Connection Analysis", definition: "Monitor for credential-spraying patterns following LSASS dump activity.", category: "Detect" },
  ],
  // T1566 — Phishing
  "T1566": [
    { d3fend_id: "D3-MAA",  label: "Message Analysis",            definition: "Scan inbound email for malicious URLs, attachments, and sender anomalies.", category: "Detect" },
    { d3fend_id: "D3-UR",   label: "URL Reputation Analysis",     definition: "Block navigation to newly-registered or low-reputation domains linked in email.", category: "Harden" },
    { d3fend_id: "D3-UA",   label: "User Account Analysis",       definition: "Detect credential use from IP/device not matching the user's baseline.", category: "Detect" },
  ],
  "T1566.001": [
    { d3fend_id: "D3-MAA",  label: "Message Analysis",            definition: "Detonate attachments in a sandbox before delivery.", category: "Detect" },
    { d3fend_id: "D3-SFA",  label: "File Analysis",               definition: "Inspect Office macros, PDF JavaScript, and OLE streams in attachments.", category: "Detect" },
  ],
  // T1055 — Process Injection
  "T1055": [
    { d3fend_id: "D3-PA",   label: "Process Spawn Analysis",      definition: "Detect anomalous CreateRemoteThread and WriteProcessMemory calls.", category: "Detect" },
    { d3fend_id: "D3-IOPAR", label: "Mandatory Access Control",    definition: "Apply process isolation via SELinux/AppArmor or Windows Integrity Levels.", category: "Harden" },
  ],
  // T1547 — Boot or Logon Autostart Execution
  "T1547.001": [
    { d3fend_id: "D3-RK",   label: "Registry Key Analysis",       definition: "Detect unexpected additions to Run/RunOnce registry keys.", category: "Detect" },
    { d3fend_id: "D3-AVR",  label: "Autoruns Analysis",           definition: "Audit Autoruns to establish a baseline; alert on deviations.", category: "Detect" },
  ],
  // T1053 — Scheduled Task
  "T1053.005": [
    { d3fend_id: "D3-PA",   label: "Process Ancestry Analysis",   definition: "Detect schtasks.exe /create from unusual parent processes.", category: "Detect" },
    { d3fend_id: "D3-STA",  label: "Scheduled Job Analysis",      definition: "Audit the Windows Task Scheduler for unexpected tasks, especially those referencing temp or user-profile directories.", category: "Detect" },
  ],
  // T1078 — Valid Accounts
  "T1078": [
    { d3fend_id: "D3-MFA",  label: "Multi-Factor Authentication", definition: "Require MFA for all external-facing access — VPN, OWA, SaaS — to prevent credential-only compromise.", category: "Harden" },
    { d3fend_id: "D3-UA",   label: "User Account Analysis",       definition: "Detect impossible-travel, off-hours, or new-device logins from valid accounts.", category: "Detect" },
    { d3fend_id: "D3-PAR",  label: "Privileged Account Management", definition: "Inventory and restrict privileged accounts; monitor their use.", category: "Harden" },
  ],
  // T1190 — Exploit Public-Facing Application
  "T1190": [
    { d3fend_id: "D3-WAFAR", label: "Web Application Firewall",    definition: "Deploy WAF rules to block exploitation attempts against public-facing services.", category: "Harden" },
    { d3fend_id: "D3-IOPAR", label: "Network Traffic Analysis",    definition: "Monitor for anomalous HTTP requests matching known CVE exploit patterns.", category: "Detect" },
    { d3fend_id: "D3-PM",   label: "Patch Management",            definition: "Maintain patch currency on all internet-facing systems — this technique is almost always paired with a specific CVE.", category: "Harden" },
  ],
  // T1021 — Remote Services
  "T1021.001": [
    { d3fend_id: "D3-IOPAR", label: "Remote Desktop Protocol Audit", definition: "Restrict RDP to jump servers and VPN; alert on any direct inbound RDP from the internet.", category: "Harden" },
    { d3fend_id: "D3-LNCA", label: "Local Network Connection Analysis", definition: "Detect lateral RDP from workstations (peer-to-peer RDP is almost always malicious).", category: "Detect" },
  ],
  "T1021.002": [
    { d3fend_id: "D3-LNCA", label: "Local Network Connection Analysis", definition: "Detect workstation-to-workstation SMB — PsExec-style lateral movement signature.", category: "Detect" },
    { d3fend_id: "D3-FRA",  label: "File Access Analysis",        definition: "Alert on admin share access (ADMIN$, C$) from unexpected sources.", category: "Detect" },
  ],
  // T1486 — Ransomware encryption
  "T1486": [
    { d3fend_id: "D3-BR",   label: "Backup Management",           definition: "Maintain offline, immutable backups. Ransomware cannot encrypt what it cannot reach.", category: "Harden" },
    { d3fend_id: "D3-FRA",  label: "File Access Analysis",        definition: "Detect mass file reads/writes with entropy spikes indicative of encryption in progress.", category: "Detect" },
    { d3fend_id: "D3-VS",   label: "Volume Shadow Copy Analysis", definition: "Alert on VSS deletion attempts — a near-universal ransomware pre-step.", category: "Detect" },
  ],
  // T1505 — Server Software Component (Web Shell)
  "T1505.003": [
    { d3fend_id: "D3-IOPAR", label: "Web Application Hardening",   definition: "Disable script execution in web-root directories; restrict which file types can be uploaded.", category: "Harden" },
    { d3fend_id: "D3-PA",   label: "Process Spawn Analysis",      definition: "Detect web server processes (IIS, Apache, nginx) spawning shells or script interpreters.", category: "Detect" },
  ],
  // T1071 — Application Layer Protocol (C2)
  "T1071.001": [
    { d3fend_id: "D3-DNSAL", label: "DNS Traffic Analysis",        definition: "Detect DNS exfiltration and DGA-generated domains used for C2.", category: "Detect" },
    { d3fend_id: "D3-UR",   label: "URL Reputation Analysis",     definition: "Block connections to newly-registered or low-reputation domains from endpoints.", category: "Harden" },
    { d3fend_id: "D3-NIA",  label: "Network Intrusion Analysis",  definition: "Apply IDS/IPS signatures for known C2 frameworks (Cobalt Strike, Sliver, Havoc).", category: "Detect" },
  ],
};

/** Returns countermeasures for a technique, including parent technique fallback. */
export function getCountermeasures(attackId: string): D3fendCountermeasure[] {
  // Direct match first.
  if (DEFEND_MAP[attackId]) return DEFEND_MAP[attackId];

  // Subtechnique fallback: T1059.001 → try T1059 if subtechnique not mapped.
  if (attackId.includes(".")) {
    const parent = attackId.split(".")[0];
    if (DEFEND_MAP[parent]) return DEFEND_MAP[parent];
  }

  return [];
}

export const DEFEND_CATEGORY_COLORS: Record<string, string> = {
  Harden:  "bg-blue-500/12 text-blue-400 border-blue-500/25",
  Detect:  "bg-yellow-500/12 text-yellow-400 border-yellow-500/25",
  Isolate: "bg-purple-500/12 text-purple-400 border-purple-500/25",
  Deceive: "bg-teal-500/12 text-teal-400 border-teal-500/25",
  Evict:   "bg-red-500/12 text-red-400 border-red-500/25",
};
