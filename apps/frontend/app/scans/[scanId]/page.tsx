"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ApiError,
  getRule,
  getScan,
  getScanFindings,
  type FindingResponse,
  type RuleDocResponse,
  type ScanStatusResponse,
} from "@/app/lib/api";
import {
  RECOMMENDATION_STYLES,
  SEVERITY_BAR_COLOR,
  SEVERITY_ORDER,
  SEVERITY_STYLES,
  formatDuration,
  formatRecommendation,
} from "@/app/lib/severity";
import { SiteHeader } from "@/app/components/site-header";
import { CodeViewer } from "@/app/components/code-viewer";
import { InfoPopover } from "@/app/components/info-popover";
import { ReportDownloadMenu } from "@/app/components/report-download-menu";
import {
  AlertIcon,
  CloseIcon,
  LinkIcon,
  SearchIcon,
  SpinnerIcon,
} from "@/app/components/icons";

type LoadState = "loading" | "not-found" | "error" | "ready";

const MAX_POLL_ATTEMPTS = 120;

const RISK_RING_COLOR: Record<string, string> = {
  CRITICAL: "text-danger",
  HIGH: "text-high",
  MEDIUM: "text-warning",
  LOW: "text-success",
};

const CATEGORY_EXPLAINERS: Record<
  string,
  {
    title: string;
    description: string;
    remediation: string;
  }
> = {
  "Code Execution": {
    title: "Code execution",
    description:
      "The scan found patterns that can run commands or execute dynamic code from untrusted input.",
    remediation: "Prefer fixed allowlists and safe wrappers over exec, eval, or shell passthrough.",
  },
  Injection: {
    title: "Injection",
    description:
      "The scan found untrusted input reaching prompts, commands, queries, or downstream tools without enough control.",
    remediation: "Validate input shape, constrain prompts, and block direct passthrough into sensitive sinks.",
  },
  "Data Leak": {
    title: "Data leak",
    description:
      "The scan found possible exposure of secrets, local files, environment values, or user data to places they should not go.",
    remediation: "Reduce data access, mask secrets, and require explicit allowlists before external transmission.",
  },
  "Privilege Escalation": {
    title: "Privilege escalation",
    description:
      "The scan found permissions or runtime settings that could let a skill act beyond its intended boundary.",
    remediation: "Drop dangerous capabilities, host access, and broad credential scope.",
  },
  "Supply Chain": {
    title: "Supply chain",
    description:
      "The scan found dependency or package trust issues such as unpinned references, risky installs, or suspicious artifacts.",
    remediation: "Pin versions, review upstream sources, and block implicit remote fetches where possible.",
  },
  "Excessive Agency": {
    title: "Excessive agency",
    description:
      "The scan found tool access or automation scope that appears broader than the skill needs for its intended task.",
    remediation: "Reduce permissions, narrow tool exposure, and require explicit user confirmation for high-impact actions.",
  },
  "Malware Signatures": {
    title: "Malware signatures",
    description:
      "The scan found patterns that resemble known malicious tooling, exploit code, droppers, miners, or other unsafe payloads.",
    remediation: "Quarantine the code path, review the matched files manually, and remove or replace suspicious artifacts.",
  },
  "MCP Hygiene": {
    title: "MCP hygiene",
    description:
      "The scan found MCP-related trust or safety issues such as broad permissions, risky defaults, or weak version controls.",
    remediation: "Apply least privilege, pin reviewed versions, and narrow tool and server scope before installation.",
  },
};

function getCategoryExplainer(label: string) {
  return CATEGORY_EXPLAINERS[label] ?? null;
}

export default function ScanDashboardPage() {
  const params = useParams<{ scanId: string }>();
  const scanId = params.scanId;

  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [scan, setScan] = useState<ScanStatusResponse | null>(null);
  const [findings, setFindings] = useState<FindingResponse[] | null>(null);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [loadingFindings, setLoadingFindings] = useState(false);

  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [selectedRule, setSelectedRule] = useState<RuleDocResponse | null>(null);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const findingsRequestKey = useMemo(
    () => JSON.stringify({ severityFilter, categoryFilter, search }),
    [severityFilter, categoryFilter, search]
  );
  const pollAttempts = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let pollHandle: ReturnType<typeof setTimeout> | null = null;

    const stopPolling = () => {
      if (pollHandle) {
        clearTimeout(pollHandle);
        pollHandle = null;
      }
    };

    async function tick() {
      pollAttempts.current += 1;
      try {
        const status = await getScan(scanId);
        if (cancelled) return;
        setScan(status);
        setLoadState("ready");

        if (status.is_terminal) {
          stopPolling();
        } else if (pollAttempts.current >= MAX_POLL_ATTEMPTS) {
          stopPolling();
          setLoadState("error");
          setErrorMessage("This scan is taking longer than expected. Refresh to check again.");
        } else {
          pollHandle = setTimeout(tick, Math.max(status.next_poll_after_ms ?? 2000, 1000));
        }
      } catch (err) {
        if (cancelled) return;
        stopPolling();
        if (err instanceof ApiError && err.status === 404) {
          setLoadState("not-found");
        } else {
          setLoadState("error");
          setErrorMessage(err instanceof Error ? err.message : "Couldn't load this scan.");
        }
      }
    }

    void tick();
    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [scanId]);

  useEffect(() => {
    let cancelled = false;

    async function loadFindings() {
      if (!scan || scan.status !== "completed") return;
      setLoadingFindings(true);
      setFindingsError(null);

      try {
        const response = await getScanFindings(scanId, {
          severity: severityFilter === "ALL" ? undefined : severityFilter,
          category: categoryFilter === "ALL" ? undefined : categoryFilter,
          q: search.trim() || undefined,
          page: 1,
          pageSize: 500,
          sort: "severity_desc",
        });
        if (!cancelled) {
          setFindings(response.findings);
          if (
            selectedFinding &&
            !response.findings.some(
              (finding) =>
                finding.id === selectedFinding.id &&
                finding.location.file === selectedFinding.location.file &&
                finding.location.start_line === selectedFinding.location.start_line
            )
          ) {
            setSelectedFinding(null);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setFindings([]);
          setFindingsError(err instanceof Error ? err.message : "Couldn't load findings.");
        }
      } finally {
        if (!cancelled) setLoadingFindings(false);
      }
    }

    void loadFindings();
    return () => {
      cancelled = true;
    };
  }, [scanId, scan, findingsRequestKey, selectedFinding, severityFilter, categoryFilter, search]);

  useEffect(() => {
    let cancelled = false;

    async function loadRule() {
      if (!selectedFinding) {
        setSelectedRule(null);
        setRuleError(null);
        return;
      }
      try {
        const rule = await getRule(selectedFinding.rule_id);
        if (!cancelled) {
          setSelectedRule(rule);
          setRuleError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setSelectedRule(null);
          setRuleError(err instanceof Error ? err.message : "Couldn't load rule details.");
        }
      }
    }

    void loadRule();
    return () => {
      cancelled = true;
    };
  }, [selectedFinding]);

  const categories = useMemo(() => {
    if (!scan) return [];
    return scan.category_breakdown.map((item) => item.label);
  }, [scan]);

  async function handleCopyLink() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // ignore clipboard failures
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader actionHref="/" actionLabel="Scan another skill" />

      {loadState === "loading" && (
        <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col items-center justify-center px-6 py-24">
          <SpinnerIcon className="h-6 w-6 animate-spin text-accent" />
          <p className="mt-4 text-sm text-muted-foreground">Loading scan…</p>
        </main>
      )}

      {loadState === "not-found" && (
        <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col items-center justify-center px-6 py-24 text-center">
          <h1 className="font-display text-2xl font-semibold text-foreground">Scan not found</h1>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            No scan exists with ID <span className="font-mono text-foreground">{scanId}</span>. It may
            have been removed, or the ID may be incorrect.
          </p>
          <Link
            href="/"
            className="mt-6 rounded-full bg-accent px-5 py-2.5 text-sm font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover"
          >
            Start a new scan
          </Link>
        </main>
      )}

      {loadState === "error" && (
        <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col items-center justify-center px-6 py-24 text-center">
          <div className="flex items-center gap-2.5 rounded-card border border-border bg-danger-bg px-5 py-4 text-sm text-danger">
            <AlertIcon className="h-4 w-4 shrink-0" />
            {errorMessage}
          </div>
          <Link
            href="/"
            className="mt-6 rounded-full border border-border px-5 py-2.5 text-sm font-medium text-foreground transition-colors duration-150 hover:border-border-strong hover:bg-muted"
          >
            Back to home
          </Link>
        </main>
      )}

      {loadState === "ready" && scan && !scan.is_terminal && (
        <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col items-center justify-center px-6 py-24">
          <div className="w-full max-w-md rounded-card border border-border bg-card p-8 text-center">
            <div className="flex items-center justify-center gap-2.5 text-sm font-medium text-foreground">
              <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
              {scan.status === "queued" ? "Queued…" : "Running deterministic analysis…"}
            </div>
            <p className="mt-2 text-sm text-muted-foreground">
              Scanning <span className="font-mono text-foreground">{scan.display_target ?? scan.target}</span>
            </p>
            <div className="mt-5 space-y-3">
              <div className="h-3 w-3/4 animate-pulse rounded-full bg-muted" />
              <div className="h-3 w-1/2 animate-pulse rounded-full bg-muted" />
              <div className="h-3 w-5/6 animate-pulse rounded-full bg-muted" />
            </div>
          </div>
        </main>
      )}

      {loadState === "ready" && scan && scan.status === "completed" && (
        <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-6 py-10">
          <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <div className="flex flex-col items-center gap-6 rounded-card border border-border bg-card p-6 sm:p-8 md:flex-row lg:col-span-8">
              <RiskRing score={scan.risk_score} severity={scan.severity} />

              <div className="flex-grow text-center md:text-left">
                <div className="mb-2 flex flex-wrap items-center justify-center gap-2 md:justify-start">
                  {scan.severity && (
                    <span
                      className={`rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-wide ${
                        SEVERITY_STYLES[scan.severity] ?? "bg-muted text-foreground"
                      }`}
                    >
                      {scan.severity}
                    </span>
                  )}
                  {scan.recommendation && (
                    <span
                      className={`rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-wide ${
                        RECOMMENDATION_STYLES[scan.recommendation] ?? "bg-muted text-foreground"
                      }`}
                    >
                      {formatRecommendation(scan.recommendation)}
                    </span>
                  )}
                  <span className="font-mono text-sm text-muted-foreground">Scan #{scan.scan_id.slice(0, 8)}</span>
                </div>
                <h1 className="font-display text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                  <span className="inline-flex items-center gap-2">
                    <span>
                      {scan.headline ?? (scan.safe_to_install === false ? "Unsafe to install" : "Safe to install")}
                    </span>
                    <InfoPopover
                      title="Install verdict"
                      description="This verdict is derived from deterministic findings only. It is a triage signal about install risk, not a guarantee of safety."
                      remediation="Review the highest-severity findings first, then re-scan after remediation."
                    />
                  </span>
                </h1>
                <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-muted-foreground md:mx-0">
                  {scan.summary ??
                    (scan.findings_count === 0
                      ? "No deterministic findings were detected in this scan."
                      : `This scan detected ${scan.findings_count} finding${
                          scan.findings_count === 1 ? "" : "s"
                        } across ${categories.length} categor${categories.length === 1 ? "y" : "ies"}.`)}
                </p>
              </div>

              <div className="flex w-full flex-col gap-2 md:w-auto">
                <div className="flex flex-wrap gap-2 md:justify-end">
                  <ReportDownloadMenu
                    scanId={scan.scan_id}
                    formats={
                      scan.report_downloads.length > 0
                        ? scan.report_downloads.map((report) => report.format)
                        : scan.available_reports
                    }
                    dark
                  />
                </div>
                <button
                  type="button"
                  onClick={handleCopyLink}
                  className="flex items-center justify-center gap-1.5 rounded-full border border-border px-4 py-2 text-xs font-medium text-foreground transition-colors duration-150 hover:border-border-strong hover:bg-muted"
                >
                  <LinkIcon className="h-3.5 w-3.5" />
                  {copied ? "Link copied" : "Copy link"}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 lg:col-span-4">
              <MetaTile label="Target" value={scan.display_target ?? scan.target} mono truncate />
              <MetaTile
                label="Mode"
                value={scan.scan_mode ?? scan.mode}
                mono
              />
              <MetaTile
                label="Total findings"
                value={String(scan.findings_count ?? 0)}
                stat
                infoTitle="Total findings"
                infoDescription="This is the normalized count of deterministic findings after the repository scan completes."
              />
              <MetaTile
                label="Duration"
                value={
                  scan.duration_seconds !== null
                    ? formatDuration(scan.started_at, scan.completed_at)
                    : "—"
                }
                stat
              />
            </div>
          </section>

          <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-card border border-border bg-card p-6">
              <h3 className="mb-5 text-sm font-medium text-foreground">Findings by severity</h3>
              <div className="space-y-4">
                {SEVERITY_ORDER.map((severity) => {
                  const count = scan.findings_by_severity[severity] ?? 0;
                  const total = scan.findings_count || 1;
                  const width = Math.min(100, (count / total) * 100);
                  return (
                    <div key={severity} className="flex items-center gap-4">
                      <span className="w-16 shrink-0 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        {severity}
                      </span>
                      <div className="h-2 flex-grow overflow-hidden rounded-full bg-muted">
                        <div
                          className={`h-full ${SEVERITY_BAR_COLOR[severity] ?? "bg-muted-foreground"}`}
                          style={{ width: `${width}%` }}
                        />
                      </div>
                      <span className="w-4 shrink-0 text-right text-sm font-semibold text-foreground">
                        {count}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="rounded-card border border-border bg-card p-6">
              <h3 className="mb-5 text-sm font-medium text-foreground">Findings by category</h3>
              {scan.category_breakdown.length === 0 ? (
                <p className="text-sm text-muted-foreground">No findings to categorize.</p>
              ) : (
                <div className="space-y-2">
                  {scan.category_breakdown.map((item) => (
                    <div
                      key={item.label}
                      className="flex items-center justify-between rounded-xl bg-muted px-4 py-3"
                    >
                      <span className="inline-flex items-center gap-2 text-sm text-foreground">
                        <span>{item.label}</span>
                        {getCategoryExplainer(item.label) ? (
                          <InfoPopover
                            title={getCategoryExplainer(item.label)!.title}
                            description={getCategoryExplainer(item.label)!.description}
                            remediation={getCategoryExplainer(item.label)!.remediation}
                          />
                        ) : null}
                      </span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {item.count} finding{item.count === 1 ? "" : "s"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>

          <section className="mt-4 flex flex-1 flex-col">
            <div className="mb-4 flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
              <h2 className="text-sm font-medium text-foreground">Scan findings</h2>
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative">
                  <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <input
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search file or category…"
                    className="w-56 rounded-full border border-border bg-card py-1.5 pl-9 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
                  />
                </div>
                <div className="flex overflow-hidden rounded-full border border-border">
                  {(["ALL", ...SEVERITY_ORDER] as const).map((severity) => (
                    <button
                      key={severity}
                      type="button"
                      onClick={() => setSeverityFilter(severity)}
                      className={`px-3 py-1.5 text-xs font-medium transition-colors duration-150 ${
                        severityFilter === severity
                          ? "bg-foreground text-background"
                          : "bg-card text-muted-foreground hover:bg-muted"
                      }`}
                    >
                      {severity === "ALL" ? "All" : severity.charAt(0) + severity.slice(1).toLowerCase()}
                    </button>
                  ))}
                </div>
                {categories.length > 0 && (
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    className="rounded-full border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
                  >
                    <option value="ALL">All categories</option>
                    {categories.map((category) => (
                      <option key={category} value={category}>
                        {category}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>

            {findingsError && (
              <div className="mb-4 flex items-center gap-2.5 rounded-card border border-border bg-danger-bg px-5 py-4 text-sm text-danger">
                <AlertIcon className="h-4 w-4 shrink-0" />
                {findingsError}
              </div>
            )}

            {!findingsError && loadingFindings && findings === null && (
              <div className="flex items-center gap-2.5 rounded-card border border-border bg-card px-5 py-4 text-sm text-muted-foreground">
                <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
                Loading findings…
              </div>
            )}

            {!findingsError && findings !== null && findings.length === 0 && (
              <div className="rounded-card border border-border bg-success-bg px-5 py-6 text-center text-sm text-success">
                No findings match the current filters.
              </div>
            )}

            {findings !== null && findings.length > 0 && (
              <div className="flex flex-1 overflow-hidden rounded-card border border-border bg-card">
                <div className="flex-1 overflow-auto">
                  <table className="w-full text-left">
                    <thead className="sticky top-0 z-10 bg-muted">
                      <tr>
                        <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          ID
                        </th>
                        <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Severity
                        </th>
                        <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Category
                        </th>
                        <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          File
                        </th>
                        <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {findings.map((finding) => {
                        const key = `${finding.id}-${finding.location.file}-${finding.location.start_line}`;
                        const isSelected =
                          selectedFinding?.id === finding.id &&
                          selectedFinding.location.file === finding.location.file &&
                          selectedFinding.location.start_line === finding.location.start_line;
                        return (
                          <tr
                            key={key}
                            className={`cursor-pointer transition-colors duration-150 hover:bg-muted ${
                              isSelected ? "bg-muted" : ""
                            }`}
                            onClick={() => setSelectedFinding(finding)}
                          >
                            <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                              {finding.rule_id}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${
                                  SEVERITY_STYLES[finding.severity] ?? "bg-muted text-muted-foreground"
                                }`}
                              >
                                {finding.severity}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-foreground">{finding.category ?? "—"}</td>
                            <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                              {finding.file_path_display ?? finding.location.file}
                            </td>
                            <td className="px-4 py-3 text-right">
                              <button
                                type="button"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setSelectedFinding(finding);
                                }}
                                className="text-xs font-medium text-accent hover:underline"
                              >
                                View
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {selectedFinding && (
                  <aside className="hidden w-96 shrink-0 flex-col border-l border-border lg:flex">
                    <div className="flex items-center justify-between border-b border-border p-6">
                      <h3 className="text-sm font-medium text-foreground">Finding details</h3>
                      <button
                        type="button"
                        onClick={() => setSelectedFinding(null)}
                        aria-label="Close finding details"
                        className="text-muted-foreground transition-colors duration-150 hover:text-foreground"
                      >
                        <CloseIcon className="h-4 w-4" />
                      </button>
                    </div>
                    <div className="flex-1 space-y-6 overflow-auto p-6">
                      <div>
                        <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Rule
                        </span>
                        <div className="flex items-start gap-2">
                          <p className="text-sm font-medium text-foreground">
                            {selectedRule?.title ?? selectedFinding.title ?? selectedFinding.rule_id}
                          </p>
                          {(selectedRule?.description || selectedFinding.explanation) ? (
                            <InfoPopover
                              title={selectedRule?.title ?? selectedFinding.title ?? selectedFinding.rule_id}
                              description={
                                selectedRule?.description ??
                                selectedFinding.explanation ??
                                "Potential security issue detected."
                              }
                              remediation={selectedRule?.remediation ?? selectedFinding.remediation ?? undefined}
                              meta={
                                selectedRule?.category ??
                                selectedFinding.category ??
                                selectedFinding.rule_family ??
                                undefined
                              }
                              align="center"
                            />
                          ) : null}
                        </div>
                        <p className="mt-1 font-mono text-xs text-muted-foreground">
                          {selectedFinding.rule_id}
                          {selectedFinding.rule_family ? ` · ${selectedFinding.rule_family}` : ""}
                        </p>
                      </div>

                      <div>
                        <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Location
                        </span>
                        <code className="font-mono text-sm text-accent">
                          {selectedFinding.file_path_display ??
                            `${selectedFinding.location.file}:${selectedFinding.location.start_line}`}
                        </code>
                      </div>

                      {selectedFinding.code_snippet && (
                        <div>
                          <span className="mb-2 block text-xs font-medium uppercase tracking-wide text-muted-foreground">
                            Vulnerable code
                          </span>
                          <CodeViewer
                            code={selectedFinding.code_snippet}
                            filePath={selectedFinding.file_path_display ?? selectedFinding.location.file}
                            startLine={selectedFinding.location.start_line || 1}
                          />
                        </div>
                      )}

                      {(selectedFinding.explanation || selectedRule?.description) && (
                        <div>
                          <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-muted-foreground">
                            Why it matters
                          </span>
                          <p className="text-sm leading-6 text-muted-foreground">
                            {selectedFinding.explanation ?? selectedRule?.description}
                          </p>
                        </div>
                      )}

                      {(selectedFinding.remediation || selectedRule?.remediation) && (
                        <div>
                          <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-muted-foreground">
                            Remediation
                          </span>
                          <p className="text-sm leading-6 text-muted-foreground">
                            {selectedFinding.remediation ?? selectedRule?.remediation}
                          </p>
                        </div>
                      )}

                      <div>
                        <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Confidence
                        </span>
                        <p className="text-sm text-foreground">{Math.round(selectedFinding.confidence * 100)}%</p>
                      </div>

                      {ruleError && (
                        <div className="rounded-xl bg-danger-bg px-4 py-3 text-sm text-danger">{ruleError}</div>
                      )}
                    </div>
                  </aside>
                )}
              </div>
            )}
          </section>
        </main>
      )}

      <footer className="border-t border-border">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center gap-2 px-6 py-6 text-xs text-muted-foreground sm:flex-row sm:justify-between">
          <span>ScanKernel</span>
          <span>Deterministic scans never execute the code they analyze.</span>
        </div>
      </footer>
    </div>
  );
}

function MetaTile({
  label,
  value,
  mono = false,
  truncate = false,
  stat = false,
  infoTitle,
  infoDescription,
  infoRemediation,
}: {
  label: string;
  value: string;
  mono?: boolean;
  truncate?: boolean;
  stat?: boolean;
  infoTitle?: string;
  infoDescription?: string;
  infoRemediation?: string;
}) {
  return (
    <div className="rounded-card border border-border bg-card p-4">
      <span className="mb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        <span>{label}</span>
        {infoTitle && infoDescription ? (
          <InfoPopover title={infoTitle} description={infoDescription} remediation={infoRemediation} />
        ) : null}
      </span>
      <span
        title={truncate ? value : undefined}
        className={`block text-foreground ${mono ? "font-mono text-sm" : ""} ${
          stat ? "font-display text-2xl font-semibold leading-tight" : ""
        } ${truncate ? "truncate" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}

function RiskRing({ score, severity }: { score: number | null; severity: string | null }) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const fraction = Math.min(100, Math.max(0, score ?? 0)) / 100;
  const offset = circumference * (1 - fraction);
  const colorClass = (severity && RISK_RING_COLOR[severity]) || "text-muted-foreground";

  return (
    <div className="relative flex h-32 w-32 shrink-0 items-center justify-center">
      <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={radius} fill="none" stroke="currentColor" strokeWidth="8" className="text-muted" />
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={colorClass}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono text-3xl font-semibold text-foreground">{score ?? "—"}</span>
        <span className="mt-1 text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Risk score</span>
      </div>
    </div>
  );
}
