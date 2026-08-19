"use client";

import { useEffect, useMemo, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from "recharts";
import type { NameType, ValueType } from "recharts/types/component/DefaultTooltipContent";
import { scanConfigurationLabel, type ScanStatusResponse } from "@/app/lib/api";
import { SHOW_RISK_SCORES } from "@/app/lib/score-visibility";

type HistoryMetric = "findings" | "risk";

interface HistoryDatum {
  scanId: string;
  createdAt: string;
  target: string;
  configurationLabel: string;
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
    <div className="min-w-60 max-w-80 rounded-lg border border-border bg-card px-3 py-2.5 shadow-xl">
      <div className="text-xs font-medium text-foreground">{datum.configurationLabel}</div>
      <div className="mt-1 text-xs text-muted-foreground">{formatTimestamp(datum.createdAt)}</div>
      <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground" title={datum.target}>{datum.target}</div>
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

export function ScanHistoryChart({ scans, metric }: { scans: ScanStatusResponse[]; metric: HistoryMetric }) {
  const reducedMotion = useReducedMotion();
  const data = useMemo<HistoryDatum[]>(
    () =>
      scans
        .filter((scan) => scan.status === "completed")
        .sort((left, right) => new Date(left.created_at).getTime() - new Date(right.created_at).getTime())
        .map((scan) => ({
          scanId: scan.scan_id,
          createdAt: scan.created_at,
          target: scan.target,
          configurationLabel: scanConfigurationLabel(scan),
          findings: scan.findings_count ?? 0,
          riskScore: scan.risk_score,
          severity: scan.severity,
          durationSeconds: scan.duration_seconds,
        })),
    [scans]
  );

  if (data.length === 0) {
    return (
      <div className="flex h-52 items-center justify-center px-6 text-center text-sm text-muted-foreground">
        No completed runs are available for this configuration.
      </div>
    );
  }

  if (data.length === 1) {
    return (
      <div className="flex h-52 flex-col items-center justify-center px-6 text-center">
        <p className="text-sm font-medium text-foreground">One completed run</p>
        <p className="mt-1 max-w-md text-xs leading-relaxed text-muted-foreground">
          Run this configuration again to see how its findings change over time.
        </p>
      </div>
    );
  }

  const metricLabel = metric === "risk" ? "Risk score" : "Findings";

  return (
    <div className="h-72 w-full" aria-label={`${metricLabel} history for the selected scan configuration`}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 12, right: 12, bottom: 4, left: 0 }} accessibilityLayer>
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
            allowDecimals={metric !== "findings"}
            domain={metric === "risk" ? [0, 100] : [0, "auto"]}
            ticks={metric === "risk" ? [0, 25, 50, 75, 100] : undefined}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={34}
          />
          <Tooltip content={HistoryTooltip} cursor={{ stroke: "var(--border-strong)", strokeDasharray: "3 3" }} />
          <Line
            type="monotone"
            dataKey={metric === "risk" ? "riskScore" : "findings"}
            name={metricLabel}
            stroke="var(--accent)"
            strokeWidth={2.5}
            dot={{ r: 3, fill: "var(--card)", strokeWidth: 2 }}
            activeDot={{ r: 5 }}
            connectNulls={false}
            isAnimationActive={!reducedMotion}
            animationDuration={450}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
