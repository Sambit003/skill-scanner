"use client";

import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { listScans, type ScanStatusResponse } from "@/app/lib/api";
import { SHOW_RISK_SCORES } from "@/app/lib/score-visibility";
import {
  RECOMMENDATION_STYLES,
  SEVERITY_ORDER,
  SEVERITY_STYLES,
  formatRecommendation,
} from "@/app/lib/severity";
import { AlertIcon, ArrowRightIcon, ChevronDownIcon, SearchIcon, SpinnerIcon } from "@/app/components/icons";

type PageState = "loading" | "ready" | "error";
type HistoryTab = "trend" | "runs";

const ScanHistoryChart = dynamic(
  () => import("@/app/components/scan-history-chart").then((module) => module.ScanHistoryChart),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-72 items-center justify-center gap-2 text-sm text-muted-foreground">
        <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
        Loading trend...
      </div>
    ),
  }
);

interface ScanGroup {
  key: string;
  name: string;
  target: string;
  scans: ScanStatusResponse[];
  latest: ScanStatusResponse;
}

interface ScanResultsSectionProps {
  compact?: boolean;
}

interface HistoryState {
  scans: ScanStatusResponse[];
  loading: boolean;
  error: string | null;
}

function canonicalTarget(target: string): string {
  const trimmed = target.trim().replace(/\/+$/, "");
  const sshMatch = trimmed.match(/^git@([^:]+):(.+)$/i);
  if (sshMatch) return `${sshMatch[1]}/${sshMatch[2]}`.replace(/\.git$/i, "").toLowerCase();

  try {
    const url = new URL(trimmed);
    return `${url.hostname}${url.pathname}`.replace(/\/+$/, "").replace(/\.git$/i, "").toLowerCase();
  } catch {
    return trimmed.replace(/\.git$/i, "").toLowerCase();
  }
}

function skillName(scan: ScanStatusResponse): string {
  const normalized = scan.target.replace(/\/+$/, "").replace(/\.git$/i, "");

  try {
    const url = new URL(normalized);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length >= 2) return `${parts.at(-2)}/${parts.at(-1)}`;
  } catch {
    const sshMatch = normalized.match(/^git@[^:]+:(.+)$/i);
    if (sshMatch) {
      const parts = sshMatch[1].split("/").filter(Boolean);
      if (parts.length >= 2) return `${parts.at(-2)}/${parts.at(-1)}`;
    }
  }

  if (scan.display_target) return scan.display_target;
  return normalized.split(/[/:]/).filter(Boolean).at(-1) ?? normalized;
}

function timestamp(scan: ScanStatusResponse): number {
  const value = new Date(scan.created_at).getTime();
  return Number.isFinite(value) ? value : 0;
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unknown date";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: date.getFullYear() === new Date().getFullYear() ? undefined : "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "--";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

function groupScans(scans: ScanStatusResponse[]): ScanGroup[] {
  const groups = new Map<string, ScanStatusResponse[]>();

  for (const scan of scans) {
    const key = canonicalTarget(scan.target);
    groups.set(key, [...(groups.get(key) ?? []), scan]);
  }

  return [...groups.entries()]
    .map(([key, group]) => {
      const sorted = [...group].sort((left, right) => timestamp(right) - timestamp(left));
      return {
        key,
        name: skillName(sorted[0]),
        target: sorted[0].target,
        scans: sorted,
        latest: sorted[0],
      };
    })
    .sort((left, right) => timestamp(right.latest) - timestamp(left.latest));
}

function ResultBadges({ scan }: { scan: ScanStatusResponse }) {
  if (scan.status !== "completed") {
    const failed = scan.status === "failed" || scan.status === "canceled";
    return (
      <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${failed ? "bg-danger-bg text-danger" : "bg-muted text-muted-foreground"}`}>
        {scan.status}
      </span>
    );
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {scan.severity && (
        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${SEVERITY_STYLES[scan.severity] ?? "bg-muted text-muted-foreground"}`}>
          {scan.severity}
        </span>
      )}
      {scan.recommendation && (
        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${RECOMMENDATION_STYLES[scan.recommendation] ?? "bg-muted text-muted-foreground"}`}>
          {formatRecommendation(scan.recommendation)}
        </span>
      )}
      {!scan.severity && !scan.recommendation && (
        <span className="rounded-full bg-muted px-2 py-0.5 text-[11px] font-semibold uppercase text-muted-foreground">
          Completed
        </span>
      )}
    </div>
  );
}

function ScanHistoryPanel({
  scans,
  loading,
  error,
  onRetry,
}: {
  scans: ScanStatusResponse[];
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}) {
  const [tab, setTab] = useState<HistoryTab>("trend");
  const sortedScans = useMemo(
    () => [...scans].sort((left, right) => timestamp(right) - timestamp(left)),
    [scans]
  );
  const completedCount = sortedScans.filter((scan) => scan.status === "completed").length;

  return (
    <div className="border-t border-border bg-background/45 px-4 py-5 lg:px-5">
      <div className="overflow-hidden rounded-lg border border-border bg-card">
        <div className="flex flex-col gap-3 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-foreground">Scan history</h2>
              {loading && <SpinnerIcon className="h-3.5 w-3.5 animate-spin text-accent" />}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {completedCount} completed {completedCount === 1 ? "run" : "runs"} across {sortedScans.length} total
            </p>
          </div>
          <div className="inline-flex w-fit overflow-hidden rounded-md border border-border bg-background p-0.5" role="tablist" aria-label="Scan history view">
            {(["trend", "runs"] as const).map((option) => (
              <button
                key={option}
                type="button"
                role="tab"
                aria-selected={tab === option}
                onClick={() => setTab(option)}
                className={`min-w-16 rounded px-3 py-1.5 text-xs font-medium transition-colors duration-150 ${
                  tab === option ? "bg-muted text-foreground" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {option === "trend" ? "Trend" : "Runs"}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="flex flex-col gap-2 border-b border-border bg-danger-bg px-4 py-3 text-xs text-danger sm:flex-row sm:items-center sm:justify-between">
            <span className="flex items-center gap-2">
              <AlertIcon className="h-3.5 w-3.5 shrink-0" />
              Complete history could not be loaded. Showing the scans already available.
            </span>
            <button type="button" onClick={onRetry} className="w-fit font-semibold underline underline-offset-2">
              Retry
            </button>
          </div>
        )}

        {tab === "trend" ? (
          <div role="tabpanel" className="px-2 pb-3 pt-4 sm:px-4">
            <ScanHistoryChart scans={sortedScans} />
            <p className="px-2 text-[11px] text-muted-foreground">
              {SHOW_RISK_SCORES
                ? "Findings use the left axis. Risk score uses the right axis from 0 to 100. Only completed runs are plotted."
                : "Findings are plotted for completed runs only."}
            </p>
          </div>
        ) : (
          <div role="tabpanel" className="max-h-[24rem] overflow-y-auto">
            <div className="sticky top-0 z-10 hidden grid-cols-[minmax(9rem,1.5fr)_minmax(11rem,1.2fr)_6rem_5rem_2rem] gap-4 border-b border-border bg-muted px-4 py-2.5 lg:grid lg:items-center">
              <span className="text-[10px] font-medium uppercase text-muted-foreground">Scanned</span>
              <span className="text-[10px] font-medium uppercase text-muted-foreground">Verdict</span>
              <span className="text-[10px] font-medium uppercase text-muted-foreground">Findings</span>
              <span className="text-[10px] font-medium uppercase text-muted-foreground">Duration</span>
              <span className="sr-only">Open</span>
            </div>
            <div className="divide-y divide-border">
              {sortedScans.map((scan, index) => (
                <div
                  key={scan.scan_id}
                  className="grid gap-3 px-4 py-3 lg:grid-cols-[minmax(9rem,1.5fr)_minmax(11rem,1.2fr)_6rem_5rem_2rem] lg:items-center lg:gap-4"
                >
                  <div className="min-w-0 text-xs text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <span>{formatDate(scan.created_at)}</span>
                      {index === 0 && (
                        <span className="rounded bg-muted px-1.5 py-0.5 text-[9px] font-semibold uppercase text-foreground">Latest</span>
                      )}
                    </div>
                    <div className="mt-1 font-mono">#{scan.scan_id.slice(0, 8)}</div>
                  </div>
                  <div>
                    <span className="mb-1 block text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Verdict</span>
                    <ResultBadges scan={scan} />
                  </div>
                  <div className="text-sm text-foreground">
                    <span className="mr-2 text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Findings</span>
                    {scan.findings_count ?? 0}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    <span className="mr-2 text-[10px] font-medium uppercase lg:hidden">Duration</span>
                    {formatDuration(scan.duration_seconds)}
                  </div>
                  <Link
                    href={`/scans/${scan.scan_id}`}
                    className="inline-flex h-8 w-8 items-center justify-center rounded-full text-accent transition-colors duration-150 hover:bg-accent/10"
                    aria-label={`Open scan ${scan.scan_id.slice(0, 8)}`}
                  >
                    <ArrowRightIcon className="h-4 w-4" />
                  </Link>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function ScanResultsSection({ compact = false }: ScanResultsSectionProps) {
  const [state, setState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [allScans, setAllScans] = useState<ScanStatusResponse[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [historyByGroup, setHistoryByGroup] = useState<Record<string, HistoryState>>({});

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const response = await listScans({ page: 1, pageSize: 100 });
        if (!cancelled) {
          setAllScans(response.items);
          setState("ready");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Couldn't load scan results.");
          setState("error");
        }
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const groups = useMemo(() => groupScans(allScans), [allScans]);
  const visibleGroups = useMemo(() => {
    const query = search.trim().toLowerCase();
    const filtered = groups.filter((group) => {
      if (severityFilter !== "ALL" && group.latest.severity !== severityFilter) return false;
      if (!query) return true;
      return (
        group.name.toLowerCase().includes(query) ||
        group.target.toLowerCase().includes(query) ||
        group.scans.some((scan) => scan.scan_id.toLowerCase().includes(query))
      );
    });
    return compact ? filtered.slice(0, 6) : filtered;
  }, [compact, groups, search, severityFilter]);

  const loadHistory = async (group: ScanGroup, force = false) => {
    if (!force && historyByGroup[group.key]) return;

    setHistoryByGroup((current) => ({
      ...current,
      [group.key]: {
        scans: current[group.key]?.scans ?? group.scans,
        loading: true,
        error: null,
      },
    }));

    try {
      const response = await listScans({ page: 1, pageSize: 100, target: group.target });
      setHistoryByGroup((current) => ({
        ...current,
        [group.key]: { scans: response.items, loading: false, error: null },
      }));
    } catch (err) {
      setHistoryByGroup((current) => ({
        ...current,
        [group.key]: {
          scans: current[group.key]?.scans ?? group.scans,
          loading: false,
          error: err instanceof Error ? err.message : "Couldn't load complete scan history.",
        },
      }));
    }
  };

  const toggleHistory = (group: ScanGroup) => {
    if (expandedGroup === group.key) {
      setExpandedGroup(null);
      return;
    }

    setExpandedGroup(group.key);
    void loadHistory(group);
  };

  return (
    <section className={`mx-auto w-full ${compact ? "max-w-6xl px-6 py-16 sm:py-20" : "max-w-[92rem] px-6 py-10"}`}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={`${compact ? "text-2xl sm:text-3xl" : "text-3xl"} font-display font-semibold tracking-tight text-foreground`}>
            Scan results
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Latest assessment per skill, with previous runs kept in its history.
          </p>
        </div>
        {compact ? (
          groups.length > 0 && (
            <Link href="/scans" className="inline-flex items-center gap-2 text-sm font-medium text-accent hover:underline">
              View all results
              <ArrowRightIcon className="h-4 w-4" />
            </Link>
          )
        ) : (
          <Link href="/" className="inline-flex items-center gap-2 rounded-full bg-accent px-4 py-2 text-sm font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover">
            New scan
            <ArrowRightIcon className="h-4 w-4" />
          </Link>
        )}
      </div>

      {!compact && (
        <div className="mt-7 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full max-w-md">
            <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search skill, target, or scan ID..."
              className="w-full rounded-full border border-border bg-card py-2 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
            />
          </div>
          <div className="flex overflow-hidden rounded-full border border-border">
            {(["ALL", ...SEVERITY_ORDER] as const).map((severity) => (
              <button
                key={severity}
                type="button"
                onClick={() => setSeverityFilter(severity)}
                className={`px-3 py-2 text-xs font-medium transition-colors duration-150 ${severityFilter === severity ? "bg-foreground text-background" : "bg-card text-muted-foreground hover:bg-muted"}`}
              >
                {severity === "ALL" ? "All" : severity.charAt(0) + severity.slice(1).toLowerCase()}
              </button>
            ))}
          </div>
        </div>
      )}

      {state === "loading" && (
        <div className="mt-7 flex items-center gap-2.5 rounded-card border border-border bg-card px-5 py-4 text-sm text-muted-foreground">
          <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
          Loading scan results...
        </div>
      )}

      {state === "error" && error && (
        <div className="mt-7 flex items-center gap-2.5 rounded-card border border-border bg-danger-bg px-5 py-4 text-sm text-danger">
          <AlertIcon className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {state === "ready" && (
        <div className="mt-7 overflow-hidden rounded-card border border-border bg-card">
          {visibleGroups.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-muted-foreground">
              {allScans.length === 0 ? "No scan results yet." : "No skills match the current filters."}
            </div>
          ) : (
            <div>
              <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1.15fr)_5rem_8.5rem_6rem_2rem] gap-4 border-b border-border bg-muted/65 px-5 py-3 lg:grid lg:items-center">
                <span className="text-[11px] font-medium uppercase text-muted-foreground">Skill</span>
                <span className="text-[11px] font-medium uppercase text-muted-foreground">Latest verdict</span>
                <span className="text-[11px] font-medium uppercase text-muted-foreground">Findings</span>
                <span className="text-[11px] font-medium uppercase text-muted-foreground">Last scanned</span>
                <span className="text-[11px] font-medium uppercase text-muted-foreground">History</span>
                <span className="sr-only">Open</span>
              </div>
              <div className="divide-y divide-border">
              {visibleGroups.map((group) => {
                const expanded = expandedGroup === group.key;
                const historyState = historyByGroup[group.key];
                const historyScans = historyState?.scans ?? group.scans;
                return (
                  <div key={group.key}>
                    <div className="grid gap-4 px-4 py-4 transition-colors duration-150 hover:bg-muted lg:grid-cols-[minmax(0,2fr)_minmax(0,1.15fr)_5rem_8.5rem_6rem_2rem] lg:items-center lg:px-5">
                      <div className="min-w-0">
                        <Link href={`/scans/${group.latest.scan_id}`} className="font-medium text-foreground hover:text-accent">
                          {group.name}
                        </Link>
                        <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{group.target}</p>
                      </div>
                      <div>
                        <span className="mb-1.5 block text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Latest verdict</span>
                        <ResultBadges scan={group.latest} />
                      </div>
                      <div>
                        <span className="mb-1.5 block text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Findings</span>
                        <span className="text-sm font-medium text-foreground">{group.latest.findings_count ?? 0}</span>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        <span className="mb-1.5 block text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Last scanned</span>
                        <div>{formatDate(group.latest.created_at)}</div>
                        <div className="mt-1 font-mono">#{group.latest.scan_id.slice(0, 8)}</div>
                      </div>
                      <div>
                        <span className="mb-1.5 block text-[10px] font-medium uppercase text-muted-foreground lg:hidden">History</span>
                        {group.scans.length > 1 ? (
                          <button
                            type="button"
                            onClick={() => toggleHistory(group)}
                            aria-expanded={expanded}
                            className="inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors duration-150 hover:bg-muted hover:text-foreground"
                          >
                            {historyScans.length} runs
                            <ChevronDownIcon className={`h-3.5 w-3.5 transition-transform duration-200 ${expanded ? "rotate-180" : ""}`} />
                          </button>
                        ) : (
                          <span className="text-xs text-muted-foreground">1 run</span>
                        )}
                      </div>
                      <Link href={`/scans/${group.latest.scan_id}`} className="inline-flex h-8 w-8 items-center justify-center rounded-full text-accent transition-colors duration-150 hover:bg-accent/10" aria-label={`Open latest ${group.name} result`}>
                        <ArrowRightIcon className="h-4 w-4" />
                      </Link>
                    </div>

                    {expanded && (
                      <ScanHistoryPanel
                        scans={historyScans}
                        loading={historyState?.loading ?? false}
                        error={historyState?.error ?? null}
                        onRetry={() => void loadHistory(group, true)}
                      />
                    )}
                  </div>
                );
              })}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
