"use client";

/**
 * Copy-defanged button for indicator detail pages.
 *
 * Analysts copy defanged IOC values constantly — into Jira tickets,
 * Slack messages, email threads, MISP events. Doing it manually
 * (select, copy, manually replace dots) is how typos happen. One click.
 */

import { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopyDefangedButton({ defanged }: { defanged: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(defanged).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Copy defanged value"
      className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink-muted transition-colors hover:bg-surface-2 hover:text-ink"
    >
      {copied ? (
        <>
          <Check className="size-4 text-ok" />
          Copied
        </>
      ) : (
        <>
          <Copy className="size-4" />
          Copy defanged
        </>
      )}
    </button>
  );
}
