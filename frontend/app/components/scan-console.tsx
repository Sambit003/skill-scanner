"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createScan, getScan, type ScanStatusResponse } from "@/app/lib/api";
import {
  loadOpenRouterSettings,
  type OpenRouterSettings,
} from "@/app/lib/byok-settings";
import { RECOMMENDATION_STYLES, SEVERITY_STYLES, formatRecommendation } from "@/app/lib/severity";
import { ByokSettingsModal } from "@/app/components/byok-settings-modal";
import { ReportDownloadMenu } from "@/app/components/report-download-menu";
import {
  AlertIcon,
  ArrowRightIcon,
  CheckIcon,
  GithubIcon,
  KeyIcon,
  SettingsIcon,
  ShieldIcon,
  SparkleIcon,
  SpinnerIcon,
} from "@/app/components/icons";

type ReviewMode = "deterministic" | "agent";
type Phase = "idle" | "loading" | "done";

const MAX_POLL_ATTEMPTS = 60;

function isLikelyValidTarget(value: string): boolean {
  if (!value) return false;
  if (/\s/.test(value)) return false;
  return true;
}

export function ScanConsole() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [reviewMode, setReviewMode] = useState<ReviewMode>("deterministic");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const [openRouterSettings, setOpenRouterSettings] = useState<OpenRouterSettings>(() =>
    loadOpenRouterSettings()
  );
  const [settingsOpen, setSettingsOpen] = useState(false);

  const pollHandle = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollAttempts = useRef(0);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key) {
        setOpenRouterSettings(loadOpenRouterSettings());
      }
    };

    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      if (pollHandle.current) clearInterval(pollHandle.current);
    };
  }, []);

  function stopPolling() {
    if (pollHandle.current) {
      clearTimeout(pollHandle.current);
      pollHandle.current = null;
    }
  }

  function pollScan(scanId: string) {
    pollAttempts.current = 0;
    const run = async () => {
      pollAttempts.current += 1;
      try {
        const status = await getScan(scanId);
        setScanStatus(status);
        if (status.status === "completed") {
          stopPolling();
          setPhase("done");
          router.push(`/scans/${status.scan_id}`);
        } else if (status.status === "failed" || status.status === "canceled") {
          stopPolling();
          setApiError(status.error ?? "The scan did not complete successfully.");
          setPhase("idle");
        } else if (pollAttempts.current >= MAX_POLL_ATTEMPTS) {
          stopPolling();
          setApiError("Scan timed out. Try again in a moment.");
          setPhase("idle");
        } else {
          pollHandle.current = setTimeout(run, Math.max(status.next_poll_after_ms ?? 2000, 1000));
        }
      } catch (err) {
        stopPolling();
        setApiError(err instanceof Error ? err.message : "Lost connection to the scan API.");
        setPhase("idle");
      }
    };
    void run();
  }

  async function handleAnalyze(event: React.FormEvent) {
    event.preventDefault();
    setFieldError(null);
    setApiError(null);

    if (!isLikelyValidTarget(target.trim())) {
      setFieldError("Enter a GitHub repository URL, local path, or skill file.");
      return;
    }

    if (reviewMode === "agent" && !openRouterSettings.apiKey.trim()) {
      setFieldError("Add your OpenRouter API key in Settings before starting agent review.");
      return;
    }

    setScanStatus(null);
    setPhase("loading");
    try {
      const created = await createScan(target.trim(), {
        agentReviewEnabled: reviewMode === "agent",
        agentReviewProvider: reviewMode === "agent" ? "openrouter" : undefined,
        agentReviewModel: reviewMode === "agent" ? openRouterSettings.model : undefined,
        agentReviewApiKey: reviewMode === "agent" ? openRouterSettings.apiKey : undefined,
      });
      pollScan(created.scan_id);
    } catch (err) {
      setApiError(err instanceof Error ? err.message : "Couldn't start the scan.");
      setPhase("idle");
    }
  }

  const isLoading = phase === "loading";
  const hasOpenRouterKey = openRouterSettings.apiKey.trim().length > 0;
  const statusLabel =
    scanStatus?.status === "queued"
      ? "Queued…"
      : scanStatus?.status === "running"
        ? reviewMode === "agent"
          ? "Running deterministic scan, then agent review…"
          : "Running static analysis…"
        : "Starting scan…";

  return (
    <div className="w-full max-w-2xl">
      <form
        onSubmit={handleAnalyze}
        className="rounded-card border border-border bg-card p-6 shadow-[0_1px_2px_rgba(28,26,23,0.04),0_12px_32px_-16px_rgba(28,26,23,0.12)] sm:p-8"
      >
        <label htmlFor="target" className="mb-2 block text-sm font-medium text-foreground">
          Repository, path, or skill file
        </label>
        <div className="relative">
          <GithubIcon className="pointer-events-none absolute left-4 top-1/2 h-4.5 w-4.5 -translate-y-1/2 text-muted-foreground" />
          <input
            id="target"
            name="target"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://github.com/org/skill-name"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              if (fieldError) setFieldError(null);
            }}
            aria-invalid={fieldError ? true : undefined}
            aria-describedby={fieldError ? "target-error" : undefined}
            className="w-full rounded-xl border border-border bg-background py-3 pl-11 pr-4 text-[15px] text-foreground placeholder:text-muted-foreground transition-colors duration-150 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
          />
        </div>
        {fieldError ? (
          <p id="target-error" className="mt-2 flex items-center gap-1.5 text-sm text-danger">
            <AlertIcon className="h-4 w-4 shrink-0" />
            {fieldError}
          </p>
        ) : (
          <p className="mt-2 text-sm text-muted-foreground">
            Public GitHub URL, a local directory path, or a single SKILL.md.
          </p>
        )}

        <div className="mt-6">
          <span className="mb-2 block text-sm font-medium text-foreground">Scan strategy</span>
          <div className="relative grid grid-cols-2 rounded-full border border-border bg-muted p-1">
            <span
              aria-hidden="true"
              className={`absolute inset-y-1 w-[calc(50%-4px)] rounded-full bg-card shadow-sm transition-transform duration-150 ease-out ${
                reviewMode === "agent" ? "translate-x-[calc(100%+8px)]" : "translate-x-0"
              }`}
            />
            <button
              type="button"
              onClick={() => setReviewMode("deterministic")}
              className={`relative z-10 flex items-center justify-center gap-1.5 rounded-full px-3 py-2 text-sm font-medium transition-colors duration-150 ${
                reviewMode === "deterministic" ? "text-foreground" : "text-muted-foreground"
              }`}
            >
              <ShieldIcon className="h-4 w-4" />
              Deterministic
            </button>
            <button
              type="button"
              onClick={() => setReviewMode("agent")}
              className={`relative z-10 flex items-center justify-center gap-1.5 rounded-full px-3 py-2 text-sm font-medium transition-colors duration-150 ${
                reviewMode === "agent" ? "text-foreground" : "text-muted-foreground"
              }`}
            >
              <SparkleIcon className="h-4 w-4" />
              + Agent review
            </button>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            {reviewMode === "deterministic"
              ? "Static parsing, pattern matching, and taint analysis only. No code execution, no LLM calls."
              : "Runs the deterministic scan first, then sends only the findings and supporting snippets to an OpenRouter model you select."}
          </p>
        </div>

        {reviewMode === "agent" && (
          <div className="mt-4 rounded-2xl border border-border bg-background p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">OpenRouter BYOK</span>
                  {hasOpenRouterKey ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-success-bg px-2 py-0.5 text-[11px] font-medium text-success">
                      <CheckIcon className="h-3 w-3" />
                      Configured
                    </span>
                  ) : (
                    <span className="rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
                      Not configured
                    </span>
                  )}
                </div>
                <p className="mt-1 text-sm text-muted-foreground">
                  Keys stay in your browser until you start a scan. For the scan itself, the key is
                  sent once and held only in memory by the backend worker.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSettingsOpen(true)}
                aria-label="Manage OpenRouter settings"
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-border text-foreground transition-colors duration-150 hover:border-border-strong hover:bg-muted"
              >
                <SettingsIcon className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-border bg-card px-4 py-3">
                <span className="block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Provider
                </span>
                <span className="mt-1 block text-sm font-medium text-foreground">OpenRouter</span>
              </div>
              <div className="rounded-xl border border-border bg-card px-4 py-3">
                <span className="block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Model
                </span>
                <span className="mt-1 block truncate font-mono text-sm text-foreground">
                  {openRouterSettings.model}
                </span>
              </div>
            </div>

            {!hasOpenRouterKey && (
              <div className="mt-4 flex items-start gap-2.5 rounded-xl bg-info-bg px-4 py-3 text-sm text-info">
                <KeyIcon className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  Add your OpenRouter API key in{" "}
                  <button
                    type="button"
                    onClick={() => setSettingsOpen(true)}
                    className="font-medium underline underline-offset-2"
                  >
                    Settings
                  </button>{" "}
                  to enable agent review.
                </span>
              </div>
            )}
          </div>
        )}

        <button
          type="submit"
          disabled={isLoading}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-full bg-accent px-5 py-3 text-[15px] font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent/40 focus:ring-offset-2 focus:ring-offset-card disabled:cursor-not-allowed disabled:opacity-70"
        >
          {isLoading ? (
            <>
              <SpinnerIcon className="h-4 w-4 animate-spin" />
              Analyzing…
            </>
          ) : (
            <>
              Analyze
              <ArrowRightIcon className="h-4 w-4" />
            </>
          )}
        </button>
      </form>

      <div className="mt-4">
        {apiError && (
          <div className="flex items-start gap-2.5 rounded-card border border-border bg-danger-bg px-5 py-4 text-sm text-danger">
            <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{apiError}</span>
          </div>
        )}

        {isLoading && (
          <div className="rounded-card border border-border bg-card p-6 sm:p-8">
            <div className="flex items-center gap-2.5 text-sm font-medium text-foreground">
              <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
              {statusLabel}
            </div>
            <div className="mt-5 space-y-3">
              <div className="h-3 w-3/4 animate-pulse rounded-full bg-muted" />
              <div className="h-3 w-1/2 animate-pulse rounded-full bg-muted" />
              <div className="h-3 w-5/6 animate-pulse rounded-full bg-muted" />
            </div>
          </div>
        )}

        {phase === "done" && scanStatus && (
          <div className="rounded-card border border-border bg-card p-6 sm:p-8">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <span className="text-3xl font-semibold tracking-tight text-foreground">
                  {scanStatus.risk_score ?? "—"}
                </span>
                <span className="text-sm text-muted-foreground">risk score</span>
              </div>
              {scanStatus.recommendation && (
                <span
                  className={`rounded-full px-3 py-1 text-sm font-medium ${
                    RECOMMENDATION_STYLES[scanStatus.recommendation] ?? "bg-muted text-foreground"
                  }`}
                >
                  {formatRecommendation(scanStatus.recommendation)}
                </span>
              )}
            </div>

            {scanStatus.headline && (
              <div className="mt-5 border-t border-border pt-5">
                <h2 className="font-display text-xl font-semibold tracking-tight text-foreground">
                  {scanStatus.headline}
                </h2>
                {scanStatus.summary && (
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
                    {scanStatus.summary}
                  </p>
                )}
              </div>
            )}

            <div className="mt-5 flex flex-wrap gap-2 border-t border-border pt-5">
              {Object.entries(scanStatus.findings_by_severity).map(([severity, count]) => (
                <span
                  key={severity}
                  className={`rounded-full px-3 py-1 text-xs font-medium ${
                    SEVERITY_STYLES[severity] ?? "bg-muted text-muted-foreground"
                  }`}
                >
                  {count} {severity.toLowerCase()}
                </span>
              ))}
              {scanStatus.findings_count === 0 && (
                <span className="rounded-full bg-success-bg px-3 py-1 text-xs font-medium text-success">
                  No findings
                </span>
              )}
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-border pt-5">
              <Link
                href={`/scans/${scanStatus.scan_id}`}
                className="rounded-full bg-foreground px-3 py-1.5 text-xs font-medium text-background transition-colors duration-150 hover:opacity-90"
              >
                View full report
              </Link>
              <ReportDownloadMenu
                scanId={scanStatus.scan_id}
                formats={
                  scanStatus.report_downloads.length > 0
                    ? scanStatus.report_downloads.map((entry) => entry.format)
                    : scanStatus.available_reports
                }
              />
            </div>
          </div>
        )}
      </div>

      {settingsOpen && (
        <ByokSettingsModal
          onClose={() => setSettingsOpen(false)}
          onSaved={setOpenRouterSettings}
        />
      )}
    </div>
  );
}
