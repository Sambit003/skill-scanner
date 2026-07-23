"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { listScans, type ScanStatusResponse } from "@/app/lib/api";
import { RECOMMENDATION_STYLES, SEVERITY_ORDER, SEVERITY_STYLES, formatRecommendation } from "@/app/lib/severity";
import { SiteHeader } from "@/app/components/site-header";
import { AlertIcon, ArrowRightIcon, SearchIcon, SpinnerIcon } from "@/app/components/icons";

type PageState = "loading" | "ready" | "error";

export default function ScansIndexPage() {
  const [state, setState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [allScans, setAllScans] = useState<ScanStatusResponse[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

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
          setError(err instanceof Error ? err.message : "Couldn't load scans.");
          setState("error");
        }
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const visibleScans = useMemo(() => {
    const query = search.trim().toLowerCase();
    return allScans.filter((scan) => {
      if (severityFilter !== "ALL" && scan.severity !== severityFilter) return false;
      if (!query) return true;
      return (
        scan.scan_id.toLowerCase().includes(query) ||
        scan.target.toLowerCase().includes(query) ||
        (scan.headline ?? "").toLowerCase().includes(query) ||
        (scan.summary ?? "").toLowerCase().includes(query)
      );
    });
  }, [allScans, search, severityFilter]);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader />

      <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-6 py-10">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="font-display text-3xl font-semibold tracking-tight text-foreground">Scans</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Recent deterministic scan jobs and their current verdicts.
            </p>
          </div>
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-full bg-accent px-4 py-2 text-sm font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover"
          >
            New scan
            <ArrowRightIcon className="h-4 w-4" />
          </Link>
        </div>

        <div className="mt-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="relative">
            <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search scan ID or target…"
              className="w-full rounded-full border border-border bg-card py-2 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25 md:w-80"
            />
          </div>
          <div className="flex overflow-hidden rounded-full border border-border">
            {(["ALL", ...SEVERITY_ORDER] as const).map((severity) => (
              <button
                key={severity}
                type="button"
                onClick={() => setSeverityFilter(severity)}
                className={`px-3 py-2 text-xs font-medium transition-colors duration-150 ${
                  severityFilter === severity
                    ? "bg-foreground text-background"
                    : "bg-card text-muted-foreground hover:bg-muted"
                }`}
              >
                {severity === "ALL" ? "All" : severity.charAt(0) + severity.slice(1).toLowerCase()}
              </button>
            ))}
          </div>
        </div>

        {state === "loading" && (
          <div className="mt-8 flex items-center gap-2.5 rounded-card border border-border bg-card px-5 py-4 text-sm text-muted-foreground">
            <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
            Loading scans…
          </div>
        )}

        {state === "error" && error && (
          <div className="mt-8 flex items-center gap-2.5 rounded-card border border-border bg-danger-bg px-5 py-4 text-sm text-danger">
            <AlertIcon className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {state === "ready" && (
          <div className="mt-8 overflow-hidden rounded-card border border-border bg-card">
            {visibleScans.length === 0 ? (
              <div className="px-6 py-12 text-center text-sm text-muted-foreground">
                No scans match the current filters.
              </div>
            ) : (
              <table className="w-full text-left">
                <thead className="bg-muted">
                  <tr>
                    <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Scan
                    </th>
                    <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Target
                    </th>
                    <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Verdict
                    </th>
                    <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Findings
                    </th>
                    <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Duration
                    </th>
                    <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Open
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {visibleScans.map((scan) => (
                    <tr key={scan.scan_id} className="transition-colors duration-150 hover:bg-muted">
                      <td className="px-4 py-4">
                        <div className="font-mono text-xs text-muted-foreground">#{scan.scan_id.slice(0, 8)}</div>
                        <div className="mt-1 text-sm font-medium text-foreground">
                          {scan.headline ?? "Scan result"}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <div className="max-w-md truncate font-mono text-xs text-muted-foreground">
                          {scan.display_target ?? scan.target}
                        </div>
                        <div className="mt-1 text-sm text-muted-foreground">{scan.status}</div>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex flex-wrap gap-2">
                          {scan.severity && (
                            <span
                              className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${
                                SEVERITY_STYLES[scan.severity] ?? "bg-muted text-muted-foreground"
                              }`}
                            >
                              {scan.severity}
                            </span>
                          )}
                          {scan.recommendation && (
                            <span
                              className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${
                                RECOMMENDATION_STYLES[scan.recommendation] ?? "bg-muted text-muted-foreground"
                              }`}
                            >
                              {formatRecommendation(scan.recommendation)}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-4 text-sm text-foreground">{scan.findings_count ?? 0}</td>
                      <td className="px-4 py-4 text-sm text-foreground">
                        {scan.duration_seconds !== null ? `${scan.duration_seconds}s` : "—"}
                      </td>
                      <td className="px-4 py-4 text-right">
                        <Link
                          href={`/scans/${scan.scan_id}`}
                          className="text-sm font-medium text-accent hover:underline"
                        >
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
