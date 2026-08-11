"use client";

import { useId, useState } from "react";

export type TrendPoint = { date: string; value: number };

/**
 * A single-series day trend — line + ~10% wash area, 2px line, end-marker
 * with a surface ring, and a hover crosshair (skill: line/area charts ship a
 * crosshair+tooltip by default, not as an extra). Genuinely computed from
 * existing timestamped rows (Indicator.createdAt, Vulnerability.publishedAt)
 * — no separate snapshot table, so the trend is real history from day one,
 * not something that only starts working after data accumulates.
 *
 * "use client": needs hover state and a stable id for the gradient def.
 * Kept in its own file, separate from charts.tsx, so that file's components
 * can stay server-rendered and accept function props from a Server Component
 * parent — see the comment there.
 */
export function TrendArea({
  data,
  color = "var(--color-chart-1)",
  height = 120,
}: {
  data: TrendPoint[];
  color?: string;
  height?: number;
}) {
  const gradientId = useId();
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  const width = 600;
  const padTop = 12;
  const padBottom = 20;
  const padX = 4;

  if (data.length === 0) {
    return <p className="px-4 py-8 text-center text-sm text-ink-faint">No data yet</p>;
  }

  const max = Math.max(...data.map((d) => d.value), 1);
  const plotH = height - padTop - padBottom;
  const stepX = data.length > 1 ? (width - padX * 2) / (data.length - 1) : 0;

  const xAt = (i: number) => padX + i * stepX;
  const yAt = (v: number) => padTop + plotH - (v / max) * plotH;

  const linePath = data.map((d, i) => `${i === 0 ? "M" : "L"}${xAt(i)},${yAt(d.value)}`).join(" ");
  const areaPath = `${linePath} L${xAt(data.length - 1)},${padTop + plotH} L${xAt(0)},${padTop + plotH} Z`;

  const hovered = hoverIndex != null ? data[hoverIndex] : null;

  return (
    <div className="relative px-4 py-3">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        style={{ height }}
        onMouseLeave={() => setHoverIndex(null)}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const relX = ((e.clientX - rect.left) / rect.width) * width;
          const i = Math.round((relX - padX) / (stepX || 1));
          setHoverIndex(Math.min(Math.max(i, 0), data.length - 1));
        }}
      >
        {/* Recessive baseline — hairline, one step off the surface. */}
        <line
          x1={padX}
          y1={padTop + plotH}
          x2={width - padX}
          y2={padTop + plotH}
          stroke="var(--color-line)"
          strokeWidth={1}
        />

        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.1} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>

        <path d={areaPath} fill={`url(#${gradientId})`} stroke="none" />
        <path d={linePath} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />

        {/* End marker: >=8px diameter, 2px surface ring. */}
        <circle cx={xAt(data.length - 1)} cy={yAt(data[data.length - 1].value)} r={5} fill={color} stroke="var(--color-surface)" strokeWidth={2} />

        {hovered && hoverIndex != null ? (
          <>
            <line
              x1={xAt(hoverIndex)}
              y1={padTop}
              x2={xAt(hoverIndex)}
              y2={padTop + plotH}
              stroke="var(--color-line-strong)"
              strokeWidth={1}
            />
            <circle cx={xAt(hoverIndex)} cy={yAt(hovered.value)} r={4} fill={color} stroke="var(--color-surface)" strokeWidth={2} />
          </>
        ) : null}

        {/* Wide invisible hit targets — easier to hover than the 2px line. */}
        {data.map((d, i) => (
          <rect
            key={d.date}
            x={xAt(i) - stepX / 2}
            y={0}
            width={stepX || width}
            height={height}
            fill="transparent"
            onMouseEnter={() => setHoverIndex(i)}
          />
        ))}
      </svg>

      <div className="mt-1 flex items-center justify-between text-[11px] text-ink-faint">
        <span>{data[0].date}</span>
        <span>{data[data.length - 1].date}</span>
      </div>

      {hovered ? (
        <div
          className="pointer-events-none absolute rounded-md border border-line bg-surface-2 px-2 py-1 text-xs text-ink shadow-lg"
          style={{
            left: `${(xAt(hoverIndex!) / width) * 100}%`,
            top: 4,
            transform: "translateX(-50%)",
          }}
        >
          <span className="text-ink-faint">{hovered.date}</span>{" "}
          <span className="tabular font-medium">{hovered.value.toLocaleString()}</span>
        </div>
      ) : null}
    </div>
  );
}
