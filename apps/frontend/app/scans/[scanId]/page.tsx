"use client";

import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ApiError,
  SCAN_SCOPE_LABELS,
  getRule,
  getScan,
  getScanFindings,
  type FindingResponse,
  type RuleDocResponse,
  type ScanStatusResponse,
} from "@/app/lib/api";
import { SHOW_RISK_SCORES } from "@/app/lib/score-visibility";
import {
  RECOMMENDATION_STYLES,
  SEVERITY_ORDER,
  SEVERITY_STYLES,
  formatDuration,
  formatRecommendation,
} from "@/app/lib/severity";
import {
  AST_CATEGORIES,
  astCategoriesForFamily,
  getRuleFamilyDoc,
} from "@/app/lib/framework";
import { SiteHeader } from "@/app/components/site-header";
import { CodeViewer } from "@/app/components/code-viewer";
import { CategoryFilterMenu } from "@/app/components/category-filter-menu";
import { InfoPopover } from "@/app/components/info-popover";
import { ReportDownloadMenu } from "@/app/components/report-download-menu";
import {
  AlertIcon,
  CloseIcon,
  InfoIcon,
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
  const [ruleDocs, setRuleDocs] = useState<Record<string, RuleDocResponse>>({});
  const [ruleDocLoading, setRuleDocLoading] = useState<Record<string, boolean>>({});
  const [ruleDocErrors, setRuleDocErrors] = useState<Record<string, string>>({});
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

  const ensureRuleDoc = useCallback(
    async (ruleId: string) => {
      if (ruleDocs[ruleId] || ruleDocLoading[ruleId]) return;

      setRuleDocLoading((current) => ({ ...current, [ruleId]: true }));
      setRuleDocErrors((current) => {
        const next = { ...current };
        delete next[ruleId];
        return next;
      });

      try {
        const rule = await getRule(ruleId);
        setRuleDocs((current) => ({ ...current, [ruleId]: rule }));
      } catch (err) {
        setRuleDocErrors((current) => ({
          ...current,
          [ruleId]: err instanceof Error ? err.message : "Couldn't load rule reference.",
        }));
      } finally {
        setRuleDocLoading((current) => ({ ...current, [ruleId]: false }));
      }
    },
    [ruleDocs, ruleDocLoading]
  );

  useEffect(() => {
    if (selectedFinding) {
      void ensureRuleDoc(selectedFinding.rule_id);
    }
  }, [ensureRuleDoc, selectedFinding]);

  const categories = useMemo(() => {
    if (!scan) return [];
    return scan.category_breakdown.map((item) => item.label);
  }, [scan]);

  const owaspAreasWithFindings = useMemo(
    () => countOwaspAreas(findings ?? []),
    [findings]
  );
  const selectedRule = selectedFinding ? ruleDocs[selectedFinding.rule_id] ?? null : null;
  const selectedRuleError = selectedFinding ? ruleDocErrors[selectedFinding.rule_id] ?? null : null;

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
        <main className="mx-auto flex w-full max-w-[92rem] flex-1 flex-col px-6 py-10">
          <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <div className="flex flex-col items-center gap-6 rounded-card border border-border bg-card p-6 sm:p-8 md:flex-row lg:col-span-8">
              {SHOW_RISK_SCORES && <RiskRing score={scan.risk_score} severity={scan.severity} />}

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
                label="Scope"
                value={`${SCAN_SCOPE_LABELS[scan.scan_scope]} · ${scan.include_readme ? "w/ README" : "w/o README"}`}
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

          <section className="mt-4 flex flex-1 flex-col">
            <div className="sticky top-[65px] z-10 mb-4 grid gap-3 rounded-card border border-border bg-background/95 px-4 py-3 backdrop-blur-md lg:grid-cols-[minmax(13rem,1fr)_auto] lg:items-center">
              <div className="min-w-0">
                <h2 className="text-sm font-medium text-foreground">Findings</h2>
                <p className="mt-0.5 max-w-md text-xs leading-5 text-muted-foreground">Mapped to OWASP review areas.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                <span className="rounded-full bg-muted px-2.5 py-1 font-mono text-[11px] text-muted-foreground">
                  {findings?.length ?? scan.findings_count ?? 0} findings
                </span>
                <span className="rounded-full bg-muted px-2.5 py-1 font-mono text-[11px] text-muted-foreground">
                  {owaspAreasWithFindings}/10 OWASP areas
                </span>
                <div className="relative w-full sm:w-64">
                  <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <input
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search file or category…"
                    className="w-full rounded-full border border-border bg-card py-1.5 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground transition-shadow duration-150 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
                  />
                </div>
                <div className="flex overflow-hidden rounded-full border border-border">
                  {(["ALL", ...SEVERITY_ORDER] as const).map((severity) => (
                    <button
                      key={severity}
                      type="button"
                      onClick={() => setSeverityFilter(severity)}
                      className={`px-2.5 py-1.5 text-[11px] font-medium transition-colors duration-150 ${
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
                  <CategoryFilterMenu
                    categories={categories}
                    value={categoryFilter}
                    onChange={setCategoryFilter}
                  />
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
              <div
                className={`grid flex-1 gap-4 transition-[grid-template-columns] duration-300 ease-out lg:items-start ${
                  selectedFinding ? "lg:grid-cols-[minmax(0,1fr)_26rem]" : "lg:grid-cols-1"
                }`}
              >
                <div className="h-[calc(100vh-14rem)] overflow-hidden rounded-card border border-border bg-card">
                  <div className="h-full overflow-y-auto">
                    <table className="w-full table-fixed text-left">
                      <colgroup>
                        <col className="w-[7%]" />
                        <col className="w-[12%]" />
                        <col className="w-[19%]" />
                        <col className="w-[8%]" />
                        <col className="w-[13%]" />
                        <col />
                      </colgroup>
                      <thead className="sticky top-0 z-[1] border-b border-border bg-muted">
                        <tr>
                          <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            Check ID
                          </th>
                          <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            OWASP area
                          </th>
                          <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            Evidence type
                          </th>
                          <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            Severity
                          </th>
                          <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            Category
                          </th>
                          <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            File
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
                              className={`group cursor-pointer transition-colors duration-150 hover:bg-muted/70 ${
                                isSelected ? "bg-muted" : "bg-card"
                              }`}
                              onClick={() => setSelectedFinding(finding)}
                            >
                              <td
                                className={`border-l-2 px-3 py-2.5 transition-colors duration-150 ${
                                  isSelected
                                    ? "border-accent text-foreground"
                                    : "border-transparent text-muted-foreground group-hover:border-border-strong"
                                }`}
                              >
                                <CheckReferenceCell
                                  finding={finding}
                                  rule={ruleDocs[finding.rule_id] ?? null}
                                  loading={ruleDocLoading[finding.rule_id] ?? false}
                                  error={ruleDocErrors[finding.rule_id] ?? null}
                                  onOpen={() => void ensureRuleDoc(finding.rule_id)}
                                />
                              </td>
                              <td className="px-3 py-2.5">
                                <OwaspReferenceBadges finding={finding} />
                              </td>
                              <td className="px-3 py-2.5">
                                <EvidenceTypeCell finding={finding} />
                              </td>
                              <td className="px-3 py-2.5">
                                <span
                                  className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${
                                    SEVERITY_STYLES[finding.severity] ?? "bg-muted text-muted-foreground"
                                  }`}
                                >
                                  {finding.severity}
                                </span>
                              </td>
                              <td className="px-3 py-2.5 text-sm leading-5 text-foreground">{finding.category ?? "—"}</td>
                              <td className="break-all px-3 py-2.5 font-mono text-xs leading-5 text-muted-foreground">
                                {finding.file_path_display ?? finding.location.file}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {selectedFinding && (
                  <aside className="animate-rail-open sticky top-[145px] hidden h-[calc(100vh-14rem)] overflow-hidden rounded-card border border-border bg-card lg:flex lg:flex-col">
                    <FindingDetailsPanel
                      key={`${selectedFinding.id}-${selectedFinding.location.file}-${selectedFinding.location.start_line}`}
                      finding={selectedFinding}
                      rule={selectedRule}
                      ruleError={selectedRuleError}
                      onClose={() => setSelectedFinding(null)}
                    />
                  </aside>
                )}
              </div>
            )}

            {selectedFinding && (
              <div className="fixed inset-0 z-30 lg:hidden">
                <button
                  type="button"
                  aria-label="Close finding details"
                  className="absolute inset-0 bg-background/65 backdrop-blur-sm"
                  onClick={() => setSelectedFinding(null)}
                />
                <div className="animate-sheet-up absolute inset-x-0 bottom-0 max-h-[82vh] overflow-hidden rounded-t-card border border-border bg-card shadow-2xl">
                  <FindingDetailsPanel
                    key={`${selectedFinding.id}-${selectedFinding.location.file}-${selectedFinding.location.start_line}-mobile`}
                    finding={selectedFinding}
                    rule={selectedRule}
                    ruleError={selectedRuleError}
                    onClose={() => setSelectedFinding(null)}
                  />
                </div>
              </div>
            )}
          </section>
        </main>
      )}

      <footer className="border-t border-border">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center gap-2 px-6 py-6 text-xs text-muted-foreground sm:flex-row sm:justify-between">
          <span>AI Skill Scanner</span>
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

type ReferenceSection = {
  label: string;
  body: string | null | undefined;
};

type ReferencePopoverPosition = {
  left: number;
  top: number;
};

function ReferencePopover({
  title,
  meta,
  sections,
  href,
  hrefLabel = "Open rule reference",
  loading = false,
  error = null,
  align = "left",
  onOpen,
  children,
}: {
  title: string;
  meta?: string;
  sections: ReferenceSection[];
  href?: string | null;
  hrefLabel?: string;
  loading?: boolean;
  error?: string | null;
  align?: "left" | "center" | "right";
  onOpen?: () => void;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<ReferencePopoverPosition>({ left: 16, top: 16 });
  const rootRef = useRef<HTMLSpanElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const popoverRef = useRef<HTMLSpanElement | null>(null);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const popoverId = useId();

  const updatePosition = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;

    const rect = trigger.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const margin = 12;
    const gap = 8;
    const popoverWidth = popoverRef.current?.offsetWidth ?? 352;
    const popoverHeight = popoverRef.current?.offsetHeight ?? 320;

    let left =
      align === "right"
        ? rect.right - popoverWidth
        : align === "center"
          ? rect.left + rect.width / 2 - popoverWidth / 2
          : rect.left;
    left = Math.max(margin, Math.min(left, viewportWidth - popoverWidth - margin));

    const below = rect.bottom + gap;
    const above = rect.top - popoverHeight - gap;
    const top = below + popoverHeight <= viewportHeight - margin ? below : Math.max(margin, above);

    setPosition({ left, top });
  }, [align]);

  const openPopover = useCallback(() => {
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
    setOpen((current) => {
      if (!current) onOpen?.();
      return true;
    });
  }, [onOpen]);

  const closePopover = useCallback(() => {
    if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
    closeTimerRef.current = setTimeout(() => setOpen(false), 120);
  }, []);

  useEffect(() => {
    if (!open) return;
    updatePosition();

    function handlePointerDown(event: MouseEvent | TouchEvent) {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("touchstart", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("touchstart", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open, updatePosition]);

  useEffect(() => {
    if (!open) return;
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);

    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open, updatePosition]);

  useEffect(() => {
    return () => {
      if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
    };
  }, []);

  useLayoutEffect(() => {
    if (open) updatePosition();
  }, [open, updatePosition, sections, loading, error]);

  function toggle(event: ReactMouseEvent<HTMLButtonElement>) {
    event.stopPropagation();
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
    setOpen((current) => {
      const next = !current;
      if (next) onOpen?.();
      return next;
    });
  }

  return (
    <span
      ref={rootRef}
      className="relative inline-flex"
      onMouseEnter={openPopover}
      onMouseLeave={closePopover}
      onFocus={openPopover}
      onBlur={(event) => {
        if (!rootRef.current?.contains(event.relatedTarget as Node | null)) {
          closePopover();
        }
      }}
    >
      <button
        ref={triggerRef}
        type="button"
        aria-label={`Reference for ${title}`}
        aria-expanded={open}
        aria-controls={popoverId}
        onClick={toggle}
        className="inline-flex items-center"
      >
        {children}
      </button>

      {open && (
        <span
          ref={popoverRef}
          id={popoverId}
          role="dialog"
          aria-label={title}
          onMouseEnter={openPopover}
          onMouseLeave={closePopover}
          onClick={(event) => event.stopPropagation()}
          style={{ left: position.left, top: position.top }}
          className="fixed z-30 w-[22rem] rounded-card border border-border bg-card p-4 text-left shadow-[0_18px_52px_rgba(0,0,0,0.24)]"
        >
          <span className="block text-sm font-semibold text-foreground">{title}</span>
          {meta ? (
            <span className="mt-1 block font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
              {meta}
            </span>
          ) : null}

          <span className="mt-3 block space-y-3">
            {loading ? (
              <span className="flex items-center gap-2 text-xs text-muted-foreground">
                <SpinnerIcon className="h-3.5 w-3.5 animate-spin text-accent" />
                Loading reference...
              </span>
            ) : null}

            {error ? (
              <span className="block rounded-xl bg-danger-bg px-3 py-2 text-xs leading-5 text-danger">
                {error}
              </span>
            ) : null}

            {sections
              .filter((section) => section.body)
              .map((section) => (
                <span key={section.label} className="block">
                  <span className="block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                    {section.label}
                  </span>
                  <span className="mt-1 block text-xs leading-5 text-muted-foreground">{section.body}</span>
                </span>
              ))}
          </span>

          {href ? (
            <a
              href={href}
              target="_blank"
              rel="noreferrer"
              className="mt-4 inline-flex items-center gap-1.5 rounded-full border border-border px-3 py-1.5 text-xs font-medium text-foreground transition-colors duration-150 hover:border-border-strong hover:bg-muted"
            >
              <LinkIcon className="h-3.5 w-3.5" />
              {hrefLabel}
            </a>
          ) : null}
        </span>
      )}
    </span>
  );
}

function CheckReferenceCell({
  finding,
  rule,
  loading,
  error,
  onOpen,
}: {
  finding: FindingResponse;
  rule: RuleDocResponse | null;
  loading: boolean;
  error: string | null;
  onOpen: () => void;
}) {
  const title = rule?.title ?? finding.title ?? finding.rule_id;
  const description = rule?.description ?? finding.explanation;
  const remediation = rule?.remediation ?? finding.remediation;
  const documentationUrl = ruleReferenceHref(finding.rule_id);
  const familyDoc = getRuleFamilyDoc(finding.rule_family);

  return (
    <span className="inline-flex max-w-full items-center gap-1.5">
      <span className="truncate font-mono text-xs">{finding.rule_id}</span>
      <ReferencePopover
        title={title}
        meta={`${finding.rule_id}${familyDoc ? ` · ${familyDoc.title}` : ""}`}
        sections={[
          { label: "Why it matters", body: description },
          { label: "Remediation", body: remediation },
        ]}
        href={documentationUrl}
        loading={loading}
        error={error}
        onOpen={onOpen}
      >
        <span className="inline-flex h-[18px] w-[18px] items-center justify-center rounded-full border border-border bg-background text-muted-foreground transition-colors duration-150 hover:border-border-strong hover:text-foreground">
          <InfoIcon className="h-3 w-3" />
        </span>
      </ReferencePopover>
    </span>
  );
}

function EvidenceTypeCell({ finding }: { finding: FindingResponse }) {
  const familyDoc = getRuleFamilyDoc(finding.rule_family);

  if (!familyDoc) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  return (
    <span title={familyDoc.summary} className="block truncate text-sm leading-5 text-foreground">
      {familyDoc.title}
    </span>
  );
}

function FindingDetailsPanel({
  finding,
  rule,
  ruleError,
  onClose,
}: {
  finding: FindingResponse;
  rule: RuleDocResponse | null;
  ruleError: string | null;
  onClose: () => void;
}) {
  return (
    <>
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <h3 className="text-sm font-medium text-foreground">Finding details</h3>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close finding details"
          className="text-muted-foreground transition-colors duration-150 hover:text-foreground"
        >
          <CloseIcon className="h-4 w-4" />
        </button>
      </div>
      <div className="animate-detail-in flex-1 space-y-5 overflow-auto p-5">
        <div>
          <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Check
          </span>
          <div className="flex items-start gap-2">
            <p className="text-sm font-medium text-foreground">{rule?.title ?? finding.title ?? finding.rule_id}</p>
            {(rule?.description || finding.explanation) ? (
              <InfoPopover
                title={rule?.title ?? finding.title ?? finding.rule_id}
                description={rule?.description ?? finding.explanation ?? "Potential security issue detected."}
                remediation={rule?.remediation ?? finding.remediation ?? undefined}
                meta={rule?.category ?? finding.category ?? finding.rule_family ?? undefined}
                align="center"
              />
            ) : null}
          </div>
          <p className="mt-1 font-mono text-xs text-muted-foreground">{finding.rule_id}</p>
        </div>

        <RuleGrouping finding={finding} />

        <FindingReferences finding={finding} rule={rule} />

        <div>
          <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Location
          </span>
          <code className="break-all font-mono text-xs text-accent">
            {finding.file_path_display ?? `${finding.location.file}:${finding.location.start_line}`}
          </code>
        </div>

        {finding.code_snippet && (
          <div>
            <span className="mb-2 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Vulnerable code
            </span>
            <CodeViewer
              code={finding.code_snippet}
              filePath={finding.file_path_display ?? finding.location.file}
              startLine={finding.location.start_line || 1}
            />
          </div>
        )}

        {(finding.explanation || rule?.description) && (
          <div>
            <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Why it matters
            </span>
            <p className="text-sm leading-6 text-muted-foreground">{finding.explanation ?? rule?.description}</p>
          </div>
        )}

        {(finding.remediation || rule?.remediation) && (
          <div>
            <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Remediation
            </span>
            <p className="text-sm leading-6 text-muted-foreground">{finding.remediation ?? rule?.remediation}</p>
          </div>
        )}

        <div>
          <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Confidence
          </span>
          <p className="text-sm text-foreground">{Math.round(finding.confidence * 100)}%</p>
        </div>

        {ruleError && <div className="rounded-xl bg-danger-bg px-4 py-3 text-sm text-danger">{ruleError}</div>}
      </div>
    </>
  );
}

function FindingReferences({ finding, rule }: { finding: FindingResponse; rule: RuleDocResponse | null }) {
  const astDocs = astCategoriesForFamily(finding.rule_family);
  const familyDoc = getRuleFamilyDoc(finding.rule_family);
  const documentationUrl = ruleReferenceHref(finding.rule_id);
  const description = rule?.description ?? finding.explanation;
  const remediation = rule?.remediation ?? finding.remediation;

  return (
    <div>
      <span className="mb-2 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        References
      </span>
      <div className="space-y-3 rounded-xl border border-border bg-background/40 px-3 py-3">
        <div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm font-medium text-foreground">{rule?.title ?? finding.title ?? finding.rule_id}</span>
            <span className="font-mono text-[11px] text-muted-foreground">{finding.rule_id}</span>
          </div>
          {familyDoc ? (
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Evidence type: <span className="text-foreground">{familyDoc.title}</span>
            </p>
          ) : null}
          {description ? <p className="mt-2 text-xs leading-5 text-muted-foreground">{description}</p> : null}
          {remediation ? (
            <p className="mt-2 rounded-lg bg-muted px-2.5 py-2 text-xs leading-5 text-foreground">{remediation}</p>
          ) : null}
          {documentationUrl ? (
            <a
              href={documentationUrl}
              target="_blank"
              rel="noreferrer"
              className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline"
            >
              <LinkIcon className="h-3.5 w-3.5" />
              Open rule reference
            </a>
          ) : null}
        </div>

        {astDocs.length > 0 ? (
          <div className="border-t border-border pt-3">
            <span className="block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              OWASP mapping
            </span>
            <div className="mt-2 space-y-2">
              {astDocs.map((category) => (
                <div key={category.id}>
                  <div className="flex items-center gap-2">
                    <span className="rounded-full border border-border px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                      {category.id}
                    </span>
                    <span className="text-xs font-medium text-foreground">{category.title}</span>
                  </div>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">{category.reviewFocus}</p>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function countOwaspAreas(findings: FindingResponse[]): number {
  const ids = new Set<string>();
  for (const finding of findings) {
    for (const category of astCategoriesForFamily(finding.rule_family)) {
      ids.add(category.id);
    }
  }
  return AST_CATEGORIES.filter((category) => ids.has(category.id)).length;
}

function OwaspReferenceBadges({ finding }: { finding: FindingResponse }) {
  const categories = astCategoriesForFamily(finding.rule_family);

  if (categories.length === 0) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {categories.slice(0, 3).map((category) => (
        <ReferencePopover
          key={category.id}
          title={`${category.id} ${category.title}`}
          meta={`OWASP · ${category.severity}`}
          sections={[
            { label: "Risk area", body: category.summary },
            { label: "Scanner evidence", body: category.scannerEvidence },
            { label: "Reviewer focus", body: category.reviewFocus },
          ]}
          align="center"
          href="/framework"
          hrefLabel="Open framework"
        >
          <span className="rounded-full border border-border px-2 py-0.5 font-mono text-[10px] text-muted-foreground transition-colors duration-150 hover:border-border-strong hover:text-foreground">
            {category.id}
          </span>
        </ReferencePopover>
      ))}
      {categories.length > 3 && (
        <span
          title={categories.slice(3).map((category) => `${category.id} ${category.title}`).join(", ")}
          className="rounded-full border border-border px-2 py-0.5 font-mono text-[10px] text-muted-foreground"
        >
          +{categories.length - 3}
        </span>
      )}
    </div>
  );
}

function ruleReferenceHref(ruleId: string): string {
  const encoded = encodeURIComponent(ruleId);
  return `/framework?rule=${encoded}#check-${encoded}`;
}

function RuleGrouping({ finding }: { finding: FindingResponse }) {
  const familyDoc = getRuleFamilyDoc(finding.rule_family);
  const astDocs = astCategoriesForFamily(finding.rule_family);

  if (!familyDoc && astDocs.length === 0) return null;

  return (
    <div>
      <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        Evidence type
      </span>
      {familyDoc && (
        <div className="rounded-xl bg-muted px-3 py-3">
          <div className="flex items-center gap-2">
            <span className="rounded-full bg-card px-2 py-0.5 font-mono text-[10px] text-accent">
              {familyDoc.id}
            </span>
            <span className="text-sm font-medium text-foreground">{familyDoc.title}</span>
          </div>
          <p className="mt-2 text-sm leading-5 text-muted-foreground">{familyDoc.summary}</p>
        </div>
      )}
      {astDocs.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {astDocs.map((category) => (
            <span
              key={category.id}
              title={category.title}
              className="rounded-full border border-border px-2 py-1 font-mono text-[11px] text-muted-foreground"
            >
              {category.id}
            </span>
          ))}
        </div>
      )}
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
