import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink } from "lucide-react";
import { db } from "@/lib/db";
import { requireUser } from "@/lib/auth/dal";
import { Card, EmptyState } from "@/components/ui/primitives";
import { PageHeader, Tag } from "@/components/ui/page";
import { FetchArticleButton } from "../fetch-article-button";

export async function generateMetadata(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const item = await db.newsItem.findUnique({ where: { id }, select: { title: true } });
  return { title: `${item?.title ?? "News"} · Pulse Intelligence` };
}

export default async function NewsDetailPage(props: { params: Promise<{ id: string }> }) {
  await requireUser();
  const { id } = await props.params;

  const item = await db.newsItem.findUnique({
    where: { id },
    include: { source: { select: { name: true } } },
  });
  if (!item) notFound();

  const actorIds = item.linkedActorIds;
  const actors = actorIds.length
    ? await db.threatActor.findMany({
        where: { id: { in: actorIds } },
        select: { id: true, name: true },
      })
    : [];

  const paragraphs = item.content ? item.content.split(/\n\n+/).filter(Boolean) : [];

  return (
    <div className="mx-auto max-w-3xl">
      <Link href="/news" className="text-xs text-ink-faint hover:text-ink">
        ← Threat News
      </Link>

      <PageHeader
        title={item.title}
        description={`${item.source?.name ?? "unknown source"} · ${item.publishedAt.toISOString().slice(0, 10)}`}
        action={
          <a
            href={item.url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
          >
            Original source
            <ExternalLink className="size-3.5" />
          </a>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        {actors.map((a) => (
          <Link
            key={a.id}
            href={`/actors/${a.id}`}
            className="rounded border border-brand/40 bg-brand/10 px-1.5 py-0.5 text-[11px] text-brand hover:bg-brand/20"
          >
            {a.name}
          </Link>
        ))}
        {item.linkedCveIds.map((cve) => (
          <Link
            key={cve}
            href={`/vulnerabilities/${cve}`}
            className="rounded border border-sev-high/40 bg-sev-high/10 px-1.5 py-0.5 font-mono text-[11px] text-sev-high hover:bg-sev-high/20"
          >
            {cve}
          </Link>
        ))}
        {item.tags.map((t) => (
          <Tag key={t}>{t}</Tag>
        ))}
      </div>

      <Card>
        {paragraphs.length > 0 ? (
          <div className="space-y-4 px-5 py-5">
            <p className="text-xs text-ink-faint">
              Full text fetched from the source page
              {item.contentFetchedAt
                ? ` on ${item.contentFetchedAt.toISOString().slice(0, 10)}`
                : ""}
              . Originally published by{" "}
              <a
                href={item.url}
                target="_blank"
                rel="noopener noreferrer nofollow"
                className="text-brand hover:underline"
              >
                {item.source?.name ?? "the source"}
              </a>
              .
            </p>
            <div className="space-y-4 text-sm leading-relaxed text-ink">
              {paragraphs.map((p, i) => (
                <p key={i}>{p}</p>
              ))}
            </div>
          </div>
        ) : (
          <div className="px-5 py-5">
            {item.summary ? (
              <p className="mb-4 text-sm leading-relaxed text-ink-muted">{item.summary}</p>
            ) : (
              <EmptyState
                title="No excerpt available"
                description="This feed didn't provide a summary. Fetch the full article to read it here."
              />
            )}
            <FetchArticleButton newsId={item.id} />
          </div>
        )}
      </Card>
    </div>
  );
}
