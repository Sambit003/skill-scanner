"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ApiError, listRules, type RuleDocResponse } from "@/app/lib/api";
import {
  AST_CATEGORIES,
  RULE_FAMILIES,
  astCategoriesForFamily,
  sortRuleIds,
} from "@/app/lib/framework";
import { SiteHeader } from "@/app/components/site-header";
import { AlertIcon, ArrowRightIcon, CloseIcon, SpinnerIcon } from "@/app/components/icons";

type PageState = "loading" | "ready" | "error";

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-danger-bg text-danger",
  High: "bg-high-bg text-high",
  Medium: "bg-warning-bg text-warning",
};

export default function FrameworkPage() {
  return (
    <Suspense fallback={<FrameworkShell />}>
      <FrameworkContent />
    </Suspense>
  );
}

function FrameworkShell() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader actionHref="/" actionLabel="New scan" />
      <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-6 py-10">
        <div className="flex items-center gap-2.5 rounded-card border border-border bg-card px-5 py-4 text-sm text-muted-foreground">
          <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
          Loading scanner checks...
        </div>
      </main>
    </div>
  );
}

function FrameworkContent() {
  const searchParams = useSearchParams();
  const selectedRuleId = searchParams.get("rule")?.toUpperCase() ?? null;
  const [state, setState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<RuleDocResponse[]>([]);

  useEffect(() => {
    let cancelled = false;

    async function loadRules() {
      try {
        const response = await listRules();
        if (!cancelled) {
          setRules([...response.items].sort((left, right) => sortRuleIds(left.rule_id, right.rule_id)));
          setState("ready");
        }
      } catch (err) {
        if (!cancelled) {
          const message =
            err instanceof ApiError
              ? err.message
              : "Couldn't load scanner check documentation.";
          setError(message);
          setState("error");
        }
      }
    }

    void loadRules();
    return () => {
      cancelled = true;
    };
  }, []);

  const rulesByFamily = useMemo(() => {
    const groups = new Map<string, RuleDocResponse[]>();
    for (const rule of rules) {
      const key = rule.rule_family.toUpperCase();
      groups.set(key, [...(groups.get(key) ?? []), rule]);
    }
    return groups;
  }, [rules]);
  const selectedRule = useMemo(
    () => rules.find((rule) => rule.rule_id.toUpperCase() === selectedRuleId) ?? null,
    [rules, selectedRuleId]
  );

  useEffect(() => {
    if (state !== "ready" || !selectedRuleId) return;

    window.requestAnimationFrame(() => {
      document.getElementById(`check-${selectedRuleId}`)?.scrollIntoView({
        block: "center",
      });
    });
  }, [selectedRuleId, state]);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader actionHref="/" actionLabel="New scan" />

      <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-6 py-10">
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Security check documentation
            </p>
            <h1 className="mt-2 font-display text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
              OWASP Agentic Skills Top 10
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-muted-foreground">
              Findings are organized around the OWASP top ten risk areas for agentic skills, so reviewers can see
              how each scan supports the security review expected before a skill is approved.
            </p>
          </div>

          <div className="rounded-card border border-border bg-card p-5">
            <h2 className="text-sm font-medium text-foreground">How to read the report</h2>
            <dl className="mt-4 space-y-3 text-sm">
              <div>
                <dt className="font-mono text-xs text-muted-foreground">AST01-AST10</dt>
                <dd className="mt-1 text-muted-foreground">
                  OWASP review areas for agentic skills, from malicious behavior to cross-platform reuse.
                </dd>
              </div>
              <div>
                <dt className="font-mono text-xs text-muted-foreground">P1, AST4, RP1</dt>
                <dd className="mt-1 text-muted-foreground">
                  Specific scanner checks that produced evidence for review.
                </dd>
              </div>
              <div>
                <dt className="font-mono text-xs text-muted-foreground">Review focus</dt>
                <dd className="mt-1 text-muted-foreground">
                  Each section explains the risk area, what the scanner looks for, and what a reviewer should examine.
                </dd>
              </div>
            </dl>
          </div>
        </section>

        <section className="mt-8">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-sm font-medium text-foreground">OWASP review areas</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Each area maps scan evidence to one of the OWASP Agentic Skills Top 10 concerns.
              </p>
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              {AST_CATEGORIES.length} review areas
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            {AST_CATEGORIES.map((category) => (
              <article key={category.id} className="rounded-card border border-border bg-card p-5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-mono text-xs font-medium text-accent">{category.id}</p>
                    <h3 className="mt-1 text-base font-semibold text-foreground">{category.title}</h3>
                  </div>
                  <span
                    className={`rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase ${
                      SEVERITY_STYLES[category.severity] ?? "bg-muted text-muted-foreground"
                    }`}
                  >
                    {category.severity}
                  </span>
                </div>

                <p className="mt-3 text-sm leading-6 text-muted-foreground">{category.summary}</p>

                <div className="mt-4 space-y-2 rounded-xl bg-muted px-4 py-3">
                  <span className="text-[11px] font-medium uppercase text-muted-foreground">What the scanner looks for</span>
                  <p className="mt-1 text-sm leading-6 text-muted-foreground">{category.scannerEvidence}</p>
                  <span className="block pt-2 text-[11px] font-medium uppercase text-muted-foreground">Reviewer focus</span>
                  <p className="text-sm leading-6 text-muted-foreground">{category.reviewFocus}</p>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {category.ruleFamilies.map((family) => (
                    <span key={family} className="rounded-full bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground">
                      {family}
                    </span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="mt-10">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-sm font-medium text-foreground">Evidence check groups</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                These check groups explain the evidence behind the OWASP review areas.
              </p>
            </div>
            {state === "ready" && (
              <span className="font-mono text-xs text-muted-foreground">Mapped to OWASP AST01-AST10</span>
            )}
          </div>

          {state === "loading" && (
            <div className="flex items-center gap-2.5 rounded-card border border-border bg-card px-5 py-4 text-sm text-muted-foreground">
              <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
              Loading scanner checks...
            </div>
          )}

          {state === "error" && error && (
            <div className="flex items-center gap-2.5 rounded-card border border-border bg-danger-bg px-5 py-4 text-sm text-danger">
              <AlertIcon className="h-4 w-4 shrink-0" />
              {error}
            </div>
          )}

          {selectedRuleId && state === "ready" && !selectedRule && (
            <div className="mb-3 rounded-card border border-border bg-warning-bg px-5 py-4 text-sm text-warning">
              No scanner documentation was found for <span className="font-mono">{selectedRuleId}</span>.
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {RULE_FAMILIES.map((family) => {
              const familyRules = rulesByFamily.get(family.id) ?? [];
              const astDocs = astCategoriesForFamily(family.id);
              const selectedFamilyRule =
                selectedRule?.rule_family.toUpperCase() === family.id ? selectedRule : null;
              return (
                <article
                  key={family.id}
                  className={`relative rounded-card border bg-card p-5 transition-colors duration-150 ${
                    selectedFamilyRule ? "z-20 border-accent/60" : "border-border"
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="font-mono text-xs font-medium text-accent">{family.id}</p>
                      <h3 className="mt-1 text-base font-semibold text-foreground">{family.title}</h3>
                    </div>
                    <span className="rounded-full bg-muted px-2.5 py-1 font-mono text-[11px] text-muted-foreground">
                      {familyRules.length || "--"} checks
                    </span>
                  </div>
                  <p className="mt-3 text-sm leading-6 text-muted-foreground">{family.summary}</p>
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {astDocs.map((category) => (
                      <span key={category.id} className="rounded-full bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground">
                        {category.id}
                      </span>
                    ))}
                  </div>
                  {familyRules.length > 0 && (
                    <div className="relative mt-4 flex flex-wrap gap-1.5">
                      {familyRules.slice(0, 14).map((rule) => {
                        const isSelected = selectedRuleId === rule.rule_id.toUpperCase();

                        return (
                          <span
                            key={rule.rule_id}
                            id={isSelected ? `check-${rule.rule_id.toUpperCase()}` : undefined}
                            className={`relative inline-flex ${isSelected ? "z-30" : ""}`}
                          >
                            <Link
                              href={`/framework?rule=${encodeURIComponent(rule.rule_id)}#check-${encodeURIComponent(rule.rule_id)}`}
                              title={rule.title}
                              className={`rounded-full border px-2 py-1 font-mono text-[11px] transition-colors duration-150 hover:border-border-strong hover:bg-muted ${
                                isSelected
                                  ? "border-accent bg-accent/10 text-accent"
                                  : "border-border text-foreground"
                              }`}
                            >
                              {rule.rule_id}
                            </Link>
                            {isSelected && selectedFamilyRule && (
                              <SelectedCheckPopover rule={selectedFamilyRule} />
                            )}
                          </span>
                        );
                      })}
                      {familyRules.length > 14 && (
                        <span className="rounded-full border border-border px-2 py-1 font-mono text-[11px] text-muted-foreground">
                          +{familyRules.length - 14}
                        </span>
                      )}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        </section>

        <section className="mt-10 rounded-card border border-border bg-card p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-sm font-medium text-foreground">Run a scan</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Use the framework view after the scan to explain each finding and its broader AST grouping.
              </p>
            </div>
            <Link
              href="/"
              className="inline-flex items-center justify-center gap-2 rounded-full bg-accent px-4 py-2 text-sm font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover"
            >
              New scan
              <ArrowRightIcon className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </main>
    </div>
  );
}

function SelectedCheckPopover({ rule }: { rule: RuleDocResponse }) {
  const router = useRouter();
  const astDocs = astCategoriesForFamily(rule.rule_family);
  const closePopover = () => router.replace("/framework", { scroll: false });

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") closePopover();
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  });

  return (
    <>
      <button
        type="button"
        onClick={closePopover}
        aria-label="Close check reference"
        className="animate-overlay-in fixed inset-0 z-40 cursor-default bg-black/65 backdrop-blur-[2px]"
      />
      <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6">
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`${rule.rule_id} check reference`}
          className="animate-popover-morph pointer-events-auto max-h-[calc(100vh-2rem)] w-full max-w-[34rem] overflow-y-auto rounded-xl border border-border-strong bg-card p-5 shadow-[0_28px_90px_rgba(0,0,0,0.5)] sm:max-h-[calc(100vh-3rem)] sm:p-6"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-full bg-accent px-2 py-0.5 font-mono text-[10px] text-accent-foreground">
                  {rule.rule_id}
                </span>
                <span className="text-xs text-muted-foreground">{rule.category}</span>
              </div>
              <h4 className="mt-2 text-lg font-semibold text-foreground">{rule.title}</h4>
            </div>
            <button
              type="button"
              onClick={closePopover}
              aria-label="Close check reference"
              className="shrink-0 rounded-full p-1.5 text-muted-foreground transition-colors duration-150 hover:bg-muted hover:text-foreground"
            >
              <CloseIcon className="h-4 w-4" />
            </button>
          </div>

          <p className="mt-3 text-sm leading-6 text-muted-foreground">{rule.description}</p>

          <div className="mt-5 grid gap-4">
            <div className="rounded-xl bg-muted px-4 py-3.5">
              <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                Remediation
              </span>
              <p className="mt-1.5 text-sm leading-6 text-foreground">{rule.remediation}</p>
            </div>
            {astDocs.length > 0 && (
              <div>
                <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  OWASP mapping
                </span>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {astDocs.map((category) => (
                    <span
                      key={category.id}
                      title={category.reviewFocus}
                      className="rounded-full border border-border px-2.5 py-1.5 text-xs text-muted-foreground"
                    >
                      <span className="font-mono text-[10px]">{category.id}</span>
                      <span className="ml-1.5 text-foreground">{category.title}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
