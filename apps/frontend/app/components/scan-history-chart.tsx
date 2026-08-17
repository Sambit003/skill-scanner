"use client";

import { useEffect, useMemo, useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceDot,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from "recharts";
import type { NameType, ValueType } from "recharts/types/component/DefaultTooltipContent";
import type { ScanStatusResponse } from "@/app/lib/api";
import { SHOW_RISK_SCORES } from "@/app/lib/score-visibility";

interface HistoryDatum {
  scanId: string;
  createdAt: string;
  findings: number;
  riskScore: number | null;
  severity: string | null;
  durationSeconds: number | null;
}

function formatTick(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "--";
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unknown date";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "--";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

function HistoryTooltip({ active, payload }: TooltipContentProps<ValueType, NameType>) {
  if (!active || !payload?.length) return null;
  const datum = payload[0]?.payload as HistoryDatum | undefined;
  if (!datum) return null;

  return (
    <div className="min-w-52 rounded-lg border border-border bg-card px-3 py-2.5 shadow-xl">
      <div className="text-xs font-medium text-foreground">{formatTimestamp(datum.createdAt)}</div>
      <div className="mt-1 font-mono text-[11px] text-muted-foreground">#{datum.scanId.slice(0, 8)}</div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-muted-foreground">Findings</dt>
        <dd className="text-right font-medium text-foreground">{datum.findings}</dd>
        {SHOW_RISK_SCORES && (
          <>
            <dt className="text-muted-foreground">Risk score</dt>
            <dd className="text-right font-medium text-foreground">{datum.riskScore ?? "--"}</dd>
          </>
        )}
        <dt className="text-muted-foreground">Severity</dt>
        <dd className="text-right font-medium text-foreground">{datum.severity ?? "--"}</dd>
        <dt className="text-muted-foreground">Duration</dt>
        <dd className="text-right font-medium text-foreground">{formatDuration(datum.durationSeconds)}</dd>
      </dl>
    </div>
  );
}

function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return reduced;
}

export function ScanHistoryChart({ scans }: { scans: ScanStatusResponse[] }) {
  const reducedMotion = useReducedMotion();
  const data = useMemo<HistoryDatum[]>(
    () =>
      scans
        .filter((scan) => scan.status === "completed")
        .sort((left, right) => new Date(left.created_at).getTime() - new Date(right.created_at).getTime())
        .map((scan) => ({
          scanId: scan.scan_id,
          createdAt: scan.created_at,
          findings: scan.findings_count ?? 0,
          riskScore: scan.risk_score,
          severity: scan.severity,
          durationSeconds: scan.duration_seconds,
        })),
    [scans]
  );

  if (data.length < 2) {
    return (
      <div className="flex h-64 items-center justify-center px-6 text-center text-sm text-muted-foreground">
        At least two completed runs are needed to draw a trend.
      </div>
    );
  }

  const latest = data.at(-1)!;

  return (
    <div
      className="h-72 w-full"
      aria-label={SHOW_RISK_SCORES ? "Historical findings and risk score chart" : "Historical findings chart"}
    >
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 8, bottom: 4, left: 0 }} accessibilityLayer>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 5" vertical={false} />
          <XAxis
            dataKey="scanId"
            tickFormatter={(scanId) => formatTick(data.find((item) => item.scanId === scanId)?.createdAt ?? "")}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: "var(--border)" }}
            interval="preserveStartEnd"
            minTickGap={36}
          />
          <YAxis
            yAxisId="findings"
            allowDecimals={false}
            domain={[0, "auto"]}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={34}
          />
          {SHOW_RISK_SCORES && (
            <YAxis
              yAxisId="risk"
              orientation="right"
              domain={[0, 100]}
              ticks={[0, 25, 50, 75, 100]}
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              width={34}
            />
          )}
          <Tooltip content={HistoryTooltip} cursor={{ stroke: "var(--border-strong)", strokeDasharray: "3 3" }} />
          <Legend
            verticalAlign="top"
            height={34}
            iconType="line"
            wrapperStyle={{ color: "var(--muted-foreground)", fontSize: 12 }}
          />
          <Line
            yAxisId="findings"
            type="monotone"
            dataKey="findings"
            name="Findings"
            stroke="var(--accent)"
            strokeWidth={2.5}
            dot={{ r: 3, fill: "var(--card)", strokeWidth: 2 }}
            activeDot={{ r: 5 }}
            isAnimationActive={!reducedMotion}
            animationDuration={450}
          />
          {SHOW_RISK_SCORES && (
            <Line
              yAxisId="risk"
              type="monotone"
              dataKey="riskScore"
              name="Risk score"
              stroke="var(--info)"
              strokeWidth={2}
              strokeDasharray="6 4"
              dot={{ r: 3, fill: "var(--card)", strokeWidth: 2 }}
              activeDot={{ r: 5 }}
              connectNulls={false}
              isAnimationActive={!reducedMotion}
              animationDuration={450}
            />
          )}
          <ReferenceDot
            yAxisId="findings"
            x={latest.scanId}
            y={latest.findings}
            r={5}
            fill="var(--card)"
            stroke="var(--accent)"
            strokeWidth={3}
          />
          {SHOW_RISK_SCORES && latest.riskScore !== null && (
            <ReferenceDot
              yAxisId="risk"
              x={latest.scanId}
              y={latest.riskScore}
              r={5}
              fill="var(--card)"
              stroke="var(--info)"
              strokeWidth={3}
            />
          )}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
