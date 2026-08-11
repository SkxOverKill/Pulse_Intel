"use client";

import { useState } from "react";
import { Check, Copy, Download } from "lucide-react";

export type ReportExportData = {
  title: string;
  summary: string | null;
  body: string;
  author: string | null;
  published: boolean;
  createdAt: string;
  updatedAt: string;
  confidence: number;
  tlp: string;
  sourceUrl: string | null;
  tags: string[];
  indicators: { type: string; value: string; confidence: number }[];
  techniques: { attackId: string; name: string; tactic: string }[];
  actors: { name: string; confidence: number }[];
};

function buildMarkdown(d: ReportExportData): string {
  const lines: string[] = [];
  lines.push(`# ${d.title}`);
  lines.push(
    `\n**TLP:${d.tlp}** · Confidence ${d.confidence}% · ${d.published ? "Published" : "Draft"}${
      d.author ? ` · ${d.author}` : ""
    } · ${d.createdAt}`,
  );
  if (d.summary) lines.push(`\n> ${d.summary}`);

  lines.push(`\n---\n`);
  lines.push(d.body);

  if (d.actors.length > 0) {
    lines.push(`\n## Attributed actors\n`);
    for (const a of d.actors) lines.push(`- **${a.name}** (confidence ${a.confidence}%)`);
  }

  if (d.techniques.length > 0) {
    lines.push(`\n## MITRE ATT&CK techniques\n`);
    lines.push(`| ID | Technique | Tactic |`);
    lines.push(`|---|---|---|`);
    for (const t of d.techniques) lines.push(`| ${t.attackId} | ${t.name} | ${t.tactic} |`);
  }

  if (d.indicators.length > 0) {
    lines.push(`\n## Indicators of compromise\n`);
    lines.push(`| Type | Value | Confidence |`);
    lines.push(`|---|---|---|`);
    for (const i of d.indicators) lines.push(`| ${i.type} | \`${i.value}\` | ${i.confidence}% |`);
  }

  if (d.tags.length > 0) lines.push(`\n**Tags:** ${d.tags.join(", ")}`);
  if (d.sourceUrl) lines.push(`\n**Source:** ${d.sourceUrl}`);

  lines.push(`\n---\n_Exported from Pulse Intelligence · ${new Date().toISOString().slice(0, 10)}_`);
  return lines.join("\n");
}

export function ReportExportActions({ data }: { data: ReportExportData }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(buildMarkdown(data));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const md = buildMarkdown(data);
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${data.title.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <button
        type="button"
        onClick={handleCopy}
        className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
      >
        {copied ? <Check className="size-3.5 text-ok" /> : <Copy className="size-3.5" />}
        {copied ? "Copied" : "Copy report"}
      </button>
      <button
        type="button"
        onClick={handleDownload}
        className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
      >
        <Download className="size-3.5" />
        Export .md
      </button>
    </>
  );
}
