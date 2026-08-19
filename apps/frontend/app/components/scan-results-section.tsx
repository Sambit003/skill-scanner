"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import {
  listScans,
  scanConfigurationKey,
  scanConfigurationLabel,
  type ScanStatusResponse,
} from "@/app/lib/api";
import { SHOW_RISK_SCORES } from "@/app/lib/score-visibility";
import {
  RECOMMENDATION_STYLES,
  SEVERITY_ORDER,
  SEVERITY_STYLES,
  formatRecommendation,
} from "@/app/lib/severity";
import { AlertIcon, ArrowRightIcon, ChevronDownIcon, InfoIcon, SearchIcon, SpinnerIcon } from "@/app/components/icons";

type PageState = "loading" | "ready" | "error";
type HistoryTab = "trend" | "compare" | "runs";
type HistoryMetric = "findings" | "risk";

interface HistoryConfiguration {
  key: string;
  label: string;
  scans: ScanStatusResponse[];
  completedScans: ScanStatusResponse[];
}

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
  const key = scan.repository_key || canonicalTarget(scan.target);
  const repositoryParts = key.split("/").filter(Boolean);
  if (!key.includes("://") && repositoryParts.length >= 3) {
    return repositoryParts.slice(1).join("/");
  }

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

function repositoryTarget(scan: ScanStatusResponse): string {
  const key = scan.repository_key || canonicalTarget(scan.target);
  return key.includes("://") ? key : `https://${key}`;
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
    const key = scan.repository_key || canonicalTarget(scan.target);
    groups.set(key, [...(groups.get(key) ?? []), scan]);
  }

  return [...groups.entries()]
    .map(([key, group]) => {
      const sorted = [...group].sort((left, right) => timestamp(right) - timestamp(left));
      return {
        key,
        name: skillName(sorted[0]),
        target: repositoryTarget(sorted[0]),
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

function findingsDelta(configuration: HistoryConfiguration): number | null {
  const [latest, previous] = configuration.completedScans;
  if (!latest || !previous) return null;
  return (latest.findings_count ?? 0) - (previous.findings_count ?? 0);
}

function formatFindingsDelta(delta: number | null): string {
  if (delta === null) return "First run";
  if (delta === 0) return "No change";
  return `${delta > 0 ? "+" : ""}${delta} vs previous`;
}

function comparisonConfigurationLabel(configuration: HistoryConfiguration): { scope: string; qualifier: string } {
  const [scope, readme] = configuration.key.split(":");
  if (scope === "skill_files") return { scope: "SKILL.md only", qualifier: "Instructions only" };
  return {
    scope: scope === "skill_folders" ? "Skill folders" : "Whole repository",
    qualifier: readme === "readme" ? "w/ README" : "w/o README",
  };
}

function FindingsDeltaBadge({ delta }: { delta: number | null }) {
  if (delta === null) {
    return <span className="inline-flex rounded-full bg-muted px-2.5 py-1 text-[11px] font-medium text-muted-foreground">No prior run</span>;
  }
  if (delta === 0) {
    return <span className="inline-flex rounded-full bg-muted px-2.5 py-1 text-[11px] font-medium text-foreground">No change</span>;
  }

  const increased = delta > 0;
  const count = Math.abs(delta);
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[11px] font-semibold ${
        increased ? "bg-warning-bg text-warning" : "bg-success-bg text-success"
      }`}
      aria-label={`${increased ? `${count} more` : `${count} fewer`} ${count === 1 ? "finding" : "findings"} than the previous equivalent run`}
    >
      <span aria-hidden="true">{increased ? "↑" : "↓"}</span>
      <span>{increased ? `+${count}` : count} {count === 1 ? "finding" : "findings"}</span>
    </span>
  );
}

function ConfigurationSelect({
  label,
  value,
  configurations,
  includeAll = false,
  totalRuns,
  onChange,
}: {
  label: string;
  value: string;
  configurations: HistoryConfiguration[];
  includeAll?: boolean;
  totalRuns: number;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const menuId = useId();
  const options = [
    ...(includeAll ? [{ value: "ALL", label: `All configurations (${totalRuns})` }] : []),
    ...configurations.map((configuration) => ({
      value: configuration.key,
      label: `${configuration.label} (${configuration.scans.length})`,
    })),
  ];
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === value));
  const selectedLabel = options[selectedIndex]?.label ?? "Select configuration";

  useEffect(() => {
    if (!open) return;

    function handlePointerDown(event: MouseEvent | TouchEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      setOpen(false);
      triggerRef.current?.focus();
    }

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("touchstart", handlePointerDown);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("touchstart", handlePointerDown);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [open]);

  function openMenu(nextIndex = selectedIndex, focusOption = false) {
    setActiveIndex(nextIndex);
    setOpen(true);
    requestAnimationFrame(() => {
      optionRefs.current[nextIndex]?.scrollIntoView({ block: "nearest" });
      if (focusOption) optionRefs.current[nextIndex]?.focus();
    });
  }

  function selectOption(nextValue: string) {
    onChange(nextValue);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function moveOption(nextIndex: number) {
    const normalizedIndex = (nextIndex + options.length) % options.length;
    setActiveIndex(normalizedIndex);
    optionRefs.current[normalizedIndex]?.focus();
  }

  return (
    <div className="flex min-w-0 items-center gap-2 text-xs font-medium text-muted-foreground">
      <span id={`${menuId}-label`} className="shrink-0">{label}</span>
      <div ref={rootRef} className="relative h-9 min-w-0">
        <div
          className={`absolute left-0 top-0 z-40 grid w-64 max-w-[calc(100vw-8rem)] overflow-hidden border bg-card transition-[grid-template-rows,border-color,border-radius,box-shadow] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] ${
            open
              ? "grid-rows-[2.25rem_1fr] rounded-xl border-accent shadow-[0_18px_44px_-18px_rgba(0,0,0,0.55)]"
              : "grid-rows-[2.25rem_0fr] rounded-[18px] border-border shadow-none"
          }`}
        >
          <button
            ref={triggerRef}
            type="button"
            aria-haspopup="listbox"
            aria-expanded={open}
            aria-controls={menuId}
            aria-labelledby={`${menuId}-label ${menuId}-value`}
            onClick={() => open ? setOpen(false) : openMenu()}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                openMenu(selectedIndex, true);
              }
            }}
            className={`grid min-h-9 grid-cols-[minmax(0,1fr)_1.25rem] items-center gap-2 px-2 pl-3.5 text-left text-xs font-medium text-foreground outline-none transition-colors duration-150 hover:bg-muted focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/25 ${open ? "bg-muted/50" : "bg-card"}`}
          >
            <span id={`${menuId}-value`} className="truncate">{selectedLabel}</span>
            <span className="flex h-5 w-5 items-center justify-center" aria-hidden="true">
              <ChevronDownIcon className={`h-3.5 w-3.5 transition-transform duration-300 ${open ? "rotate-180" : ""}`} />
            </span>
          </button>

          <div className="min-h-0 overflow-hidden">
            <div
              id={menuId}
              role="listbox"
              aria-labelledby={`${menuId}-label`}
              aria-hidden={!open}
              className={`max-h-64 overflow-y-auto border-t border-border p-1.5 transition-[opacity,transform] duration-200 ${
                open
                  ? "visible translate-y-0 opacity-100 delay-75"
                  : "invisible -translate-y-1 opacity-0 delay-0"
              }`}
            >
              {options.map((option, index) => {
                const selected = option.value === value;
                return (
                  <button
                    key={option.value}
                    ref={(node) => { optionRefs.current[index] = node; }}
                    type="button"
                    role="option"
                    aria-selected={selected}
                    tabIndex={open && index === activeIndex ? 0 : -1}
                    onMouseEnter={() => setActiveIndex(index)}
                    onClick={() => selectOption(option.value)}
                    onKeyDown={(event) => {
                      if (event.key === "ArrowDown") {
                        event.preventDefault();
                        moveOption(activeIndex + 1);
                      } else if (event.key === "ArrowUp") {
                        event.preventDefault();
                        moveOption(activeIndex - 1);
                      } else if (event.key === "Home") {
                        event.preventDefault();
                        moveOption(0);
                      } else if (event.key === "End") {
                        event.preventDefault();
                        moveOption(options.length - 1);
                      } else if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        selectOption(option.value);
                      }
                    }}
                    className={`relative block w-full rounded-md px-3.5 py-2 text-left text-xs outline-none transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/25 ${
                      selected ? "bg-muted font-medium text-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:bg-muted focus-visible:text-foreground"
                    }`}
                  >
                    {selected && <span aria-hidden="true" className="absolute bottom-2 left-1.5 top-2 w-0.5 rounded-full bg-accent" />}
                    <span className="whitespace-nowrap">{option.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
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
  const [metric, setMetric] = useState<HistoryMetric>("findings");
  const [trendConfiguration, setTrendConfiguration] = useState<string | null>(null);
  const [runsConfiguration, setRunsConfiguration] = useState("ALL");
  const sortedScans = useMemo(
    () => [...scans].sort((left, right) => timestamp(right) - timestamp(left)),
    [scans]
  );
  const completedCount = sortedScans.filter((scan) => scan.status === "completed").length;
  const configurations = useMemo<HistoryConfiguration[]>(() => {
    const items = new Map<string, ScanStatusResponse[]>();
    for (const scan of sortedScans) {
      const key = scanConfigurationKey(scan);
      items.set(key, [...(items.get(key) ?? []), scan]);
    }
    const order = ["skill_files:no-readme", "skill_folders:no-readme", "skill_folders:readme", "repository:no-readme", "repository:readme"];
    return [...items.entries()]
      .map(([key, configurationScans]) => ({
        key,
        label: scanConfigurationLabel(configurationScans[0]),
        scans: configurationScans,
        completedScans: configurationScans.filter((scan) => scan.status === "completed"),
      }))
      .sort((left, right) => order.indexOf(left.key) - order.indexOf(right.key));
  }, [sortedScans]);
  const latestConfigurationKey = sortedScans[0] ? scanConfigurationKey(sortedScans[0]) : null;
  const selectedTrendKey = trendConfiguration && configurations.some((configuration) => configuration.key === trendConfiguration)
    ? trendConfiguration
    : latestConfigurationKey ?? configurations[0]?.key ?? "";
  const selectedTrend = configurations.find((configuration) => configuration.key === selectedTrendKey) ?? null;
  const filteredRuns = runsConfiguration === "ALL"
    ? sortedScans
    : sortedScans.filter((scan) => scanConfigurationKey(scan) === runsConfiguration);

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
              {sortedScans.length} {sortedScans.length === 1 ? "run" : "runs"} · {configurations.length} {configurations.length === 1 ? "configuration" : "configurations"}
              {completedCount !== sortedScans.length ? ` · ${completedCount} completed` : ""}
            </p>
          </div>
          <div className="inline-flex w-fit overflow-hidden rounded-md border border-border bg-background p-0.5" role="tablist" aria-label="Scan history view">
            {(["trend", "compare", "runs"] as const).map((option) => (
              <button
                key={option}
                type="button"
                role="tab"
                aria-selected={tab === option}
                aria-controls={`scan-history-${option}-panel`}
                onClick={() => setTab(option)}
                className={`min-w-20 rounded px-3 py-1.5 text-xs font-medium transition-colors duration-150 ${
                  tab === option ? "bg-muted text-foreground" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {option === "trend" ? "Trend" : option === "compare" ? "Compare" : "Runs"}
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

        {tab === "trend" && (
          <div id="scan-history-trend-panel" role="tabpanel">
            <div className="flex flex-col gap-3 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <ConfigurationSelect
                label="Configuration"
                value={selectedTrendKey}
                configurations={configurations}
                totalRuns={sortedScans.length}
                onChange={setTrendConfiguration}
              />
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">
                  {selectedTrend?.completedScans.length ?? 0} completed {(selectedTrend?.completedScans.length ?? 0) === 1 ? "run" : "runs"}
                </span>
                {SHOW_RISK_SCORES && (
                  <div className="inline-flex overflow-hidden rounded-md border border-border bg-background p-0.5" aria-label="Chart metric">
                    {(["findings", "risk"] as const).map((option) => (
                      <button
                        key={option}
                        type="button"
                        aria-pressed={metric === option}
                        onClick={() => setMetric(option)}
                        className={`rounded px-2.5 py-1 text-xs font-medium ${
                          metric === option ? "bg-muted text-foreground" : "text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        {option === "findings" ? "Findings" : "Risk score"}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {selectedTrend?.completedScans[0] ? (
              <>
                <div className="grid border-b border-border sm:grid-cols-2 lg:grid-cols-4 lg:divide-x lg:divide-border">
                  <div className="px-4 py-3">
                    <p className="text-[10px] font-medium uppercase text-muted-foreground">Latest findings</p>
                    <p className="mt-1 text-xl font-semibold text-foreground">{selectedTrend.completedScans[0].findings_count ?? 0}</p>
                  </div>
                  <div className="px-4 py-3">
                    <p className="text-[10px] font-medium uppercase text-muted-foreground">Change</p>
                    <p className="mt-1 text-sm font-medium text-foreground">{formatFindingsDelta(findingsDelta(selectedTrend))}</p>
                  </div>
                  <div className="px-4 py-3">
                    <p className="text-[10px] font-medium uppercase text-muted-foreground">Latest verdict</p>
                    <div className="mt-1.5"><ResultBadges scan={selectedTrend.completedScans[0]} /></div>
                  </div>
                  <div className="px-4 py-3">
                    <p className="text-[10px] font-medium uppercase text-muted-foreground">Last scanned</p>
                    <p className="mt-1 text-xs text-foreground">{formatDate(selectedTrend.completedScans[0].created_at)}</p>
                  </div>
                </div>
                <div className="px-2 pb-3 pt-4 sm:px-4">
                  <ScanHistoryChart scans={selectedTrend.scans} metric={metric} />
                  <p className="px-2 text-[11px] text-muted-foreground">
                    {metric === "risk" ? "Risk score" : "Findings"} for equivalent completed scans only.
                  </p>
                </div>
              </>
            ) : (
              <div className="px-6 py-12 text-center text-sm text-muted-foreground">No completed runs are available for this configuration.</div>
            )}
          </div>
        )}

        {tab === "compare" && (
          <div id="scan-history-compare-panel" role="tabpanel" className="p-4">
            <div className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
              <InfoIcon className="mt-0.5 h-4 w-4 shrink-0 text-info" />
              <p>Compare the latest completed run for each configuration. Finding totals reflect different coverage.</p>
            </div>

            <div className="mt-4 hidden overflow-x-auto rounded-lg border border-border lg:block">
              <table className="w-full min-w-[760px] table-fixed border-collapse bg-background text-left">
                <caption className="sr-only">Latest completed scan results compared by configuration</caption>
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    <th scope="col" className="w-40 px-4 py-4 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                      Compare
                    </th>
                    {configurations.map((configuration) => {
                      const label = comparisonConfigurationLabel(configuration);
                      const isLatestConfiguration = configuration.key === latestConfigurationKey;
                      return (
                        <th key={configuration.key} scope="col" className="border-l border-border p-0 align-top">
                          <div className={`min-h-24 border-t-2 px-4 py-3.5 ${isLatestConfiguration ? "border-accent" : "border-transparent"}`}>
                            <div className="flex min-h-5 items-center">
                              {isLatestConfiguration && (
                                <span className="text-[9px] font-semibold uppercase tracking-wide text-accent">Latest used</span>
                              )}
                            </div>
                            <p className="mt-1 text-sm font-semibold text-foreground">{label.scope}</p>
                            <p className="mt-0.5 text-xs font-normal text-muted-foreground">{label.qualifier}</p>
                          </div>
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  <tr>
                    <th scope="row" className="px-4 py-3 text-xs font-medium text-muted-foreground">Latest verdict</th>
                    {configurations.map((configuration) => (
                      <td key={configuration.key} className="border-l border-border px-4 py-3">
                        {configuration.completedScans[0] ? <ResultBadges scan={configuration.completedScans[0]} /> : <span className="text-xs text-muted-foreground">Unavailable</span>}
                      </td>
                    ))}
                  </tr>
                  <tr>
                    <th scope="row" className="px-4 py-3 text-xs font-medium text-muted-foreground">Latest findings</th>
                    {configurations.map((configuration) => (
                      <td key={configuration.key} className="border-l border-border px-4 py-3 text-xl font-semibold text-foreground">
                        {configuration.completedScans[0]?.findings_count ?? (configuration.completedScans[0] ? 0 : "—")}
                      </td>
                    ))}
                  </tr>
                  <tr>
                    <th scope="row" className="px-4 py-3 text-xs font-medium leading-5 text-muted-foreground">
                      Change
                      <span className="block text-[10px] font-normal">vs prior same configuration</span>
                    </th>
                    {configurations.map((configuration) => (
                      <td key={configuration.key} className="border-l border-border px-4 py-3">
                        {configuration.completedScans[0] ? <FindingsDeltaBadge delta={findingsDelta(configuration)} /> : <span className="text-xs text-muted-foreground">—</span>}
                      </td>
                    ))}
                  </tr>
                  <tr>
                    <th scope="row" className="px-4 py-3 text-xs font-medium text-muted-foreground">Last scanned</th>
                    {configurations.map((configuration) => (
                      <td key={configuration.key} className="border-l border-border px-4 py-3 text-xs text-foreground">
                        {configuration.completedScans[0] ? formatDate(configuration.completedScans[0].created_at) : "—"}
                      </td>
                    ))}
                  </tr>
                  <tr>
                    <th scope="row" className="px-4 py-3 text-xs font-medium text-muted-foreground">Completed runs</th>
                    {configurations.map((configuration) => (
                      <td key={configuration.key} className="border-l border-border px-4 py-3 text-xs text-foreground">
                        {configuration.completedScans.length}
                      </td>
                    ))}
                  </tr>
                  <tr>
                    <th scope="row" className="px-4 py-3"><span className="sr-only">Result</span></th>
                    {configurations.map((configuration) => {
                      const latest = configuration.completedScans[0];
                      return (
                        <td key={configuration.key} className="border-l border-border px-4 py-3">
                          {latest ? (
                            <Link href={`/scans/${latest.scan_id}`} className="inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline focus-visible:rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/30">
                              View result <ArrowRightIcon className="h-3.5 w-3.5" />
                            </Link>
                          ) : <span className="text-xs text-muted-foreground">No result</span>}
                        </td>
                      );
                    })}
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:hidden">
              {configurations.map((configuration) => {
                const latest = configuration.completedScans[0];
                const isLatestConfiguration = configuration.key === latestConfigurationKey;
                const label = comparisonConfigurationLabel(configuration);
                return (
                  <article key={configuration.key} className={`rounded-lg border border-border border-t-2 bg-background p-4 ${isLatestConfiguration ? "border-t-accent" : "border-t-border"}`}>
                    <div className="flex min-h-5 items-center justify-between gap-3">
                      <p className="text-xs text-muted-foreground">{label.qualifier}</p>
                      {isLatestConfiguration && <span className="text-[9px] font-semibold uppercase tracking-wide text-accent">Latest used</span>}
                    </div>
                    <h3 className="mt-1 text-sm font-semibold text-foreground">{label.scope}</h3>
                    {latest ? (
                      <>
                        <div className="mt-3"><ResultBadges scan={latest} /></div>
                        <dl className="mt-4 grid grid-cols-2 items-center gap-x-4 gap-y-3 text-xs">
                          <dt className="text-muted-foreground">Latest findings</dt>
                          <dd className="text-right text-lg font-semibold text-foreground">{latest.findings_count ?? 0}</dd>
                          <dt className="leading-4 text-muted-foreground">Change <span className="block text-[10px]">vs prior same config</span></dt>
                          <dd className="text-right"><FindingsDeltaBadge delta={findingsDelta(configuration)} /></dd>
                          <dt className="text-muted-foreground">Last scanned</dt>
                          <dd className="text-right text-foreground">{formatDate(latest.created_at)}</dd>
                          <dt className="text-muted-foreground">Completed runs</dt>
                          <dd className="text-right text-foreground">{configuration.completedScans.length}</dd>
                        </dl>
                        <Link href={`/scans/${latest.scan_id}`} className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline focus-visible:rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/30">
                          View result <ArrowRightIcon className="h-3.5 w-3.5" />
                        </Link>
                      </>
                    ) : (
                      <p className="mt-4 text-xs text-muted-foreground">No completed runs yet.</p>
                    )}
                  </article>
                );
              })}
            </div>
          </div>
        )}

        {tab === "runs" && (
          <div id="scan-history-runs-panel" role="tabpanel">
            <div className="flex flex-col gap-2 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <ConfigurationSelect
                label="Filter"
                value={runsConfiguration}
                configurations={configurations}
                includeAll
                totalRuns={sortedScans.length}
                onChange={setRunsConfiguration}
              />
              <span className="text-xs text-muted-foreground">{filteredRuns.length} of {sortedScans.length} runs</span>
            </div>
            <div className="max-h-[24rem] overflow-y-auto">
              <div className="sticky top-0 z-10 hidden grid-cols-[minmax(9rem,1.1fr)_minmax(12rem,1.35fr)_minmax(11rem,1.15fr)_minmax(10rem,1fr)_5rem_5rem_2rem] gap-4 border-b border-border bg-muted px-4 py-2.5 lg:grid lg:items-center">
                <span className="text-[10px] font-medium uppercase text-muted-foreground">Scanned</span>
                <span className="text-[10px] font-medium uppercase text-muted-foreground">Target</span>
                <span className="text-[10px] font-medium uppercase text-muted-foreground">Configuration</span>
                <span className="text-[10px] font-medium uppercase text-muted-foreground">Verdict</span>
                <span className="text-[10px] font-medium uppercase text-muted-foreground">Findings</span>
                <span className="text-[10px] font-medium uppercase text-muted-foreground">Duration</span>
                <span className="sr-only">Open</span>
              </div>
              <div className="divide-y divide-border">
                {filteredRuns.map((scan, index) => (
                  <div key={scan.scan_id} className="grid gap-3 px-4 py-3 lg:grid-cols-[minmax(9rem,1.1fr)_minmax(12rem,1.35fr)_minmax(11rem,1.15fr)_minmax(10rem,1fr)_5rem_5rem_2rem] lg:items-center lg:gap-4">
                    <div className="min-w-0 text-xs text-muted-foreground">
                      <div className="flex items-center gap-2">
                        <span>{formatDate(scan.created_at)}</span>
                        {index === 0 && <span className="rounded bg-muted px-1.5 py-0.5 text-[9px] font-semibold uppercase text-foreground">Latest shown</span>}
                      </div>
                      <div className="mt-1 font-mono">#{scan.scan_id.slice(0, 8)}</div>
                    </div>
                    <div className="min-w-0 text-xs text-muted-foreground">
                      <span className="mb-1 block text-[10px] font-medium uppercase lg:hidden">Target</span>
                      <div className="truncate font-mono" title={scan.target}>{scan.target}</div>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <span className="mb-1 block text-[10px] font-medium uppercase lg:hidden">Configuration</span>
                      {scanConfigurationLabel(scan)}
                    </div>
                    <div><span className="mb-1 block text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Verdict</span><ResultBadges scan={scan} /></div>
                    <div className="text-sm text-foreground"><span className="mr-2 text-[10px] font-medium uppercase text-muted-foreground lg:hidden">Findings</span>{scan.findings_count ?? 0}</div>
                    <div className="text-xs text-muted-foreground"><span className="mr-2 text-[10px] font-medium uppercase lg:hidden">Duration</span>{formatDuration(scan.duration_seconds)}</div>
                    <Link href={`/scans/${scan.scan_id}`} className="inline-flex h-8 w-8 items-center justify-center rounded-full text-accent transition-colors duration-150 hover:bg-accent/10" aria-label={`Open scan ${scan.scan_id.slice(0, 8)}`}>
                      <ArrowRightIcon className="h-4 w-4" />
                    </Link>
                  </div>
                ))}
              </div>
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
      const response = await listScans({
        page: 1,
        pageSize: 100,
        repositoryKey: group.key,
      });
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
                        <p className="mt-1 text-xs text-muted-foreground">
                          Latest: {scanConfigurationLabel(group.latest)}
                        </p>
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
