"use client";

import { useRef } from "react";
import { X } from "lucide-react";
import { addAlias, removeAlias } from "../actions";

type Alias = {
  id: string;
  alias: string;
  namedBy: string | null;
  addedBy: string | null;
};

/**
 * Aliases carry who uses the name. "APT29", "Cozy Bear", "Midnight Blizzard"
 * and "NOBELIUM" are four vendors naming one actor — recording the vendor is
 * what makes a cross-report pivot possible later.
 */
export function AliasManager({
  actorId,
  aliases,
  canEdit,
}: {
  actorId: string;
  aliases: Alias[];
  canEdit: boolean;
}) {
  const formRef = useRef<HTMLFormElement>(null);

  return (
    <div>
      {aliases.length === 0 ? (
        <p className="px-4 py-4 text-sm text-ink-faint">
          No aliases recorded yet.
        </p>
      ) : (
        <ul className="divide-y divide-line/60">
          {aliases.map((a) => (
            <li key={a.id} className="flex items-center gap-3 px-4 py-2.5">
              <span className="text-sm text-ink">{a.alias}</span>
              {a.namedBy ? (
                <span className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-[11px] text-ink-muted">
                  {a.namedBy}
                </span>
              ) : (
                <span className="text-[11px] text-ink-faint">source not recorded</span>
              )}
              <span className="ml-auto text-[11px] text-ink-faint">
                {a.addedBy ? `added by ${a.addedBy}` : null}
              </span>
              {canEdit ? (
                <form action={removeAlias}>
                  <input type="hidden" name="id" value={a.id} />
                  <input type="hidden" name="actorId" value={actorId} />
                  <button
                    type="submit"
                    title={`Remove alias ${a.alias}`}
                    className="grid size-6 place-items-center rounded text-ink-faint hover:bg-surface-2 hover:text-danger"
                  >
                    <X className="size-3.5" />
                  </button>
                </form>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      {canEdit ? (
        <form
          ref={formRef}
          action={async (fd) => {
            await addAlias(fd);
            formRef.current?.reset();
          }}
          className="flex items-center gap-2 border-t border-line px-4 py-3"
        >
          <input type="hidden" name="actorId" value={actorId} />
          <input
            name="alias"
            required
            placeholder="Cozy Bear"
            className="min-w-0 flex-1 rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
          />
          <input
            name="namedBy"
            placeholder="CrowdStrike"
            className="w-40 rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:border-brand focus:outline-none"
          />
          <button
            type="submit"
            className="rounded-md bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-hover"
          >
            Add
          </button>
        </form>
      ) : null}
    </div>
  );
}
