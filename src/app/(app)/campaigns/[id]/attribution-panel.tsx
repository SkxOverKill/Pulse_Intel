"use client";

import Link from "next/link";
import { useRef, useState } from "react";
import { X } from "lucide-react";
import { ConfidenceBar } from "@/components/ui/primitives";
import { linkActor, unlinkActor } from "../actions";

type Attribution = {
  actorId: string;
  name: string;
  country: string | null;
  confidence: number;
  addedBy: string | null;
};

/**
 * Attribution always shows its confidence and who recorded it. A campaign
 * attributed at 30% by one analyst reads very differently from one at 90%, and
 * flattening that distinction is how intel platforms manufacture false certainty.
 */
export function AttributionPanel({
  campaignId,
  attributions,
  availableActors,
  canEdit,
}: {
  campaignId: string;
  attributions: Attribution[];
  availableActors: { id: string; name: string }[];
  canEdit: boolean;
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const [confidence, setConfidence] = useState(50);

  return (
    <div>
      {attributions.length === 0 ? (
        <p className="px-4 py-4 text-sm text-ink-faint">
          Unattributed. Activity clusters often stay nameless for a long time —
          that is a legitimate state, not a gap to fill with a guess.
        </p>
      ) : (
        <ul className="divide-y divide-line/60">
          {attributions.map((a) => (
            <li key={a.actorId} className="flex items-center gap-3 px-4 py-2.5">
              <Link
                href={`/actors/${a.actorId}`}
                className="text-sm text-ink hover:text-brand"
              >
                {a.name}
              </Link>
              {a.country ? (
                <span className="text-xs text-ink-faint">{a.country}</span>
              ) : null}
              <span className="ml-auto flex items-center gap-3">
                <ConfidenceBar value={a.confidence} />
                {a.addedBy ? (
                  <span className="text-[11px] text-ink-faint">by {a.addedBy}</span>
                ) : null}
                {canEdit ? (
                  <form action={unlinkActor}>
                    <input type="hidden" name="campaignId" value={campaignId} />
                    <input type="hidden" name="actorId" value={a.actorId} />
                    <button
                      type="submit"
                      title={`Remove attribution to ${a.name}`}
                      className="grid size-6 place-items-center rounded text-ink-faint hover:bg-surface-2 hover:text-danger"
                    >
                      <X className="size-3.5" />
                    </button>
                  </form>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      )}

      {canEdit && availableActors.length > 0 ? (
        <form
          ref={formRef}
          action={async (fd) => {
            await linkActor(fd);
            formRef.current?.reset();
            setConfidence(50);
          }}
          className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3"
        >
          <input type="hidden" name="campaignId" value={campaignId} />
          <select
            name="actorId"
            required
            defaultValue=""
            className="min-w-40 flex-1 rounded-md border border-line bg-base px-2.5 py-1.5 text-sm text-ink focus:border-brand focus:outline-none"
          >
            <option value="" disabled>
              Attribute to actor…
            </option>
            {availableActors.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-xs text-ink-muted">
            Confidence
            <input
              type="range"
              name="confidence"
              min={0}
              max={100}
              step={5}
              value={confidence}
              onChange={(e) => setConfidence(Number(e.target.value))}
              className="h-1.5 w-24 cursor-pointer appearance-none rounded-full bg-surface-3 accent-brand"
            />
            <span className="tabular w-8 text-right">{confidence}%</span>
          </label>
          <button
            type="submit"
            className="rounded-md bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-hover"
          >
            Attribute
          </button>
        </form>
      ) : null}
    </div>
  );
}
