"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createScan, getScan, type ScanStatusResponse } from "@/app/lib/api";
import { RECOMMENDATION_STYLES, SEVERITY_STYLES, formatRecommendation } from "@/app/lib/severity";
import { ReportDownloadMenu } from "@/app/components/report-download-menu";
import {
  AlertIcon,
  ArrowRightIcon,
  GithubIcon,
  ShieldIcon,
  SpinnerIcon,
} from "@/app/components/icons";

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
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);

  const pollHandle = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollAttempts = useRef(0);

  useEffect(() => {
    return () => {
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

    setScanStatus(null);
    setPhase("loading");
    try {
      const created = await createScan(target.trim());
      pollScan(created.scan_id);
    } catch (err) {
      setApiError(err instanceof Error ? err.message : "Couldn't start the scan.");
      setPhase("idle");
    }
  }

  const isLoading = phase === "loading";
  const statusLabel =
    scanStatus?.status === "queued"
      ? "Queued…"
      : scanStatus?.status === "running"
        ? "Running deterministic analysis…"
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
          <div className="flex items-center gap-2 rounded-xl border border-border bg-muted px-4 py-3 text-sm font-medium text-foreground">
              <ShieldIcon className="h-4 w-4" />
              Deterministic
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Static parsing, pattern matching, and taint analysis only. No code execution or external model calls.
          </p>
        </div>

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

    </div>
  );
}
