"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ApiError, listRules, type RuleDocResponse } from "@/app/lib/api";
import {
  AST_CATEGORIES,
  LLM_CATEGORIES,
  NIST_GAI_RISKS,
  NIST_RMF_SUBCATEGORIES,
  RULE_FAMILIES,
  astCategoriesForFamily,
  getLlmCategoryDoc,
  getNistGaiRiskDoc,
  getNistRmfDoc,
  getFrameworksForFinding,
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
  const [activeTab, setActiveTab] = useState<"ast" | "llm" | "nist">("ast");
  const [state, setState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<RuleDocResponse[]>([]);

  useEffect(() => {
    let active = true;

    listRules()
      .then((data) => {
        if (!active) return;
        setRules(data.items);
        setState("ready");
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof ApiError ? err.message : "Failed to load scanner rules.");
        setState("error");
      });

    return () => {
      active = false;
    };
  }, []);

  const rulesByFamily = useMemo(() => {
    const grouped = new Map<string, RuleDocResponse[]>();
    for (const rule of rules) {
      const family = rule.rule_family.toUpperCase();
      const existing = grouped.get(family) ?? [];
      existing.push(rule);
      grouped.set(family, existing);
    }
    for (const [, familyRules] of grouped) {
      familyRules.sort((left, right) => sortRuleIds(left.rule_id, right.rule_id));
    }
    return grouped;
  }, [rules]);

  const selectedRule = useMemo(() => {
    if (!selectedRuleId) return null;
    return rules.find((item) => item.rule_id.toUpperCase() === selectedRuleId) ?? null;
  }, [rules, selectedRuleId]);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader actionHref="/" actionLabel="New scan" />

      <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col px-6 py-10">
        <nav aria-label="Breadcrumb" className="mb-4 text-xs text-muted-foreground">
          <Link href="/" className="transition-colors duration-150 hover:text-foreground">
            Scans
          </Link>
          <span className="mx-1.5 text-border-strong">/</span>
          <span className="text-foreground">Security Frameworks</span>
        </nav>

        <section className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
              OWASP &amp; NIST Framework Alignment
            </h1>
            <p className="mt-2.5 text-sm leading-6 text-muted-foreground">
              Findings are organized across OWASP Agentic Skills Top 10, OWASP GenAI LLM Top 10, and NIST AI frameworks to support comprehensive risk assessment.
            </p>
          </div>

          <div className="rounded-card border border-border bg-card p-5">
            <h2 className="text-sm font-medium text-foreground">Mapping Hierarchy</h2>
            <dl className="mt-4 space-y-3 text-sm">
              <div>
                <dt className="font-mono text-xs text-accent">1. Primary Taxonomy</dt>
                <dd className="mt-0.5 text-xs text-muted-foreground">
                  OWASP Agentic Skills Top 10 (AST01–AST10) classifies skill risks.
                </dd>
              </div>
              <div>
                <dt className="font-mono text-xs text-accent">2. Applied Mechanisms</dt>
                <dd className="mt-0.5 text-xs text-muted-foreground">
                  OWASP GenAI LLM Top 10 (2026) identifies vulnerability mechanisms where applicable.
                </dd>
              </div>
              <div>
                <dt className="font-mono text-xs text-accent">3. Governance Alignment</dt>
                <dd className="mt-0.5 text-xs text-muted-foreground">
                  NIST AI 600-1 primary risks and AI RMF 1.0 subcategories provide enterprise traceability.
                </dd>
              </div>
            </dl>
          </div>
        </section>

        {/* Framework Selector Tabs */}
        <div className="mt-8 border-b border-border">
          <div className="flex gap-6">
            <button
              type="button"
              onClick={() => setActiveTab("ast")}
              className={`pb-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === "ast"
                  ? "border-accent text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              OWASP Agentic Skills (AST01–AST10)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("llm")}
              className={`pb-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === "llm"
                  ? "border-accent text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              OWASP GenAI LLM Top 10 (2026)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("nist")}
              className={`pb-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === "nist"
                  ? "border-accent text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              NIST AI Risk Alignment (AI 600-1 &amp; RMF)
            </button>
          </div>
        </div>

        {/* Tab 1: AST */}
        {activeTab === "ast" && (
          <section className="mt-6">
            <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-sm font-medium text-foreground">OWASP Agentic Skills Review Areas</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Primary taxonomy organizing skill-specific risks into 10 key review areas.
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
        )}

        {/* Tab 2: LLM 2026 */}
        {activeTab === "llm" && (
          <section className="mt-6">
            <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-sm font-medium text-foreground">OWASP GenAI LLM Top 10 (2026)</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Applied where vulnerability mechanisms intersect with agent skill static analysis.
                </p>
              </div>
              <span className="font-mono text-xs text-muted-foreground">
                {LLM_CATEGORIES.length} categories
              </span>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {LLM_CATEGORIES.map((cat) => (
                <article key={cat.id} className="rounded-card border border-border bg-card p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-mono text-xs font-semibold text-accent">{cat.id}</p>
                      <h3 className="mt-1 text-base font-semibold text-foreground">{cat.title}</h3>
                    </div>
                    <span
                      className={`rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase ${
                        SEVERITY_STYLES[cat.severity] ?? "bg-muted text-muted-foreground"
                      }`}
                    >
                      {cat.severity}
                    </span>
                  </div>

                    <p className="mt-3 text-sm leading-6 text-muted-foreground">{cat.summary}</p>

                    <div className="mt-4 rounded-xl bg-muted px-4 py-3">
                      <span className="text-[11px] font-medium uppercase text-muted-foreground">Static Scanner Evidence</span>
                      <p className="mt-1 text-sm leading-6 text-foreground">{cat.scannerEvidence}</p>
                    </div>

                    <div className="mt-4">
                      <span className="text-[11px] font-medium uppercase text-muted-foreground">Key Mitigations</span>
                      <ul className="mt-1.5 list-disc space-y-1 pl-4 text-xs text-muted-foreground">
                        {cat.mitigations.map((m, i) => (
                          <li key={i}>{m}</li>
                        ))}
                      </ul>
                    </div>
                  </article>
                ))}
              </div>
          </section>
        )}

        {/* Tab 3: NIST */}
        {activeTab === "nist" && (
          <section className="mt-6 space-y-8">
            <div>
              <div className="mb-4">
                <h2 className="text-sm font-medium text-foreground">NIST AI 600-1 Generative AI Primary Risks</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Risks categorized according to the NIST Generative AI Risk Management Profile (AI 600-1).
                </p>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {Object.values(NIST_GAI_RISKS).map((risk) => (
                  <article key={risk.id} className="rounded-card border border-border bg-card p-5">
                    <h3 className="text-base font-semibold text-foreground">{risk.title}</h3>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">{risk.summary}</p>
                    <div className="mt-4 rounded-xl bg-muted px-4 py-3">
                      <span className="text-[11px] font-medium uppercase text-muted-foreground">Scan Evidence Alignment</span>
                      <p className="mt-1 text-sm leading-6 text-foreground">{risk.whatFindingsEvidence}</p>
                    </div>
                  </article>
                ))}
              </div>
            </div>

            <div>
              <div className="mb-4">
                <h2 className="text-sm font-medium text-foreground">NIST AI RMF 1.0 Subcategories Supported</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Specific subcategories in the NIST AI Risk Management Framework 1.0 supported by static evidence.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                {Object.values(NIST_RMF_SUBCATEGORIES).map((sub) => (
                  <article key={sub.id} className="rounded-card border border-border bg-card p-4">
                    <div className="flex items-center gap-2">
                      <span className="rounded-full bg-accent/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-accent">
                        {sub.id}
                      </span>
                      <span className="text-xs text-muted-foreground">{sub.function}</span>
                    </div>
                    <p className="mt-2.5 text-xs leading-5 text-muted-foreground">{sub.summary}</p>
                    <p className="mt-2 border-t border-border pt-2 text-[11px] text-foreground/80">{sub.howScannerSupports}</p>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* Evidence Check Groups */}
        <section className="mt-10">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-sm font-medium text-foreground">Evidence check groups</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Detailed scanner check groups and their multi-framework mappings.
              </p>
            </div>
            {state === "ready" && (
              <span className="font-mono text-xs text-muted-foreground">Mapped to OWASP &amp; NIST</span>
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
              The requested scanner documentation is not available.
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {RULE_FAMILIES.map((family) => {
              const familyRules = rulesByFamily.get(family.id) ?? [];
              const astDocs = astCategoriesForFamily(family.id);
              return (
                <article
                  key={family.id}
                  className="flex flex-col justify-between rounded-card border border-border bg-card p-5"
                >
                  <div>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-mono text-xs font-semibold text-accent">{family.id}</p>
                        <h3 className="mt-1 text-base font-semibold text-foreground">{family.title}</h3>
                      </div>
                      <span className="font-mono text-xs text-muted-foreground">
                        {familyRules.length} checks
                      </span>
                    </div>

                    <p className="mt-3 text-sm leading-6 text-muted-foreground">{family.summary}</p>

                    {astDocs.length > 0 && (
                      <div className="mt-4 flex flex-wrap gap-1.5">
                        {astDocs.map((category) => (
                          <span
                            key={category.id}
                            className="rounded-full bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground"
                          >
                            {category.id}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="mt-5 border-t border-border pt-4">
                    <div className="flex flex-wrap gap-1.5">
                      {familyRules.map((rule) => (
                        <Link
                          key={rule.rule_id}
                          href={`/framework?rule=${rule.rule_id}`}
                          scroll={false}
                          className={`rounded-full border px-2.5 py-1 font-mono text-xs transition-colors duration-150 ${
                            selectedRuleId === rule.rule_id
                              ? "border-accent bg-accent text-accent-foreground"
                              : "border-border text-muted-foreground hover:border-border-strong hover:text-foreground"
                          }`}
                        >
                          {rule.rule_id}
                        </Link>
                      ))}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        {selectedRule && <SelectedCheckPopover rule={selectedRule} />}
      </main>
    </div>
  );
}

function SelectedCheckPopover({ rule }: { rule: RuleDocResponse }) {
  const router = useRouter();
  const closePopover = () => router.replace("/framework", { scroll: false });

  const fwResult = getFrameworksForFinding({
    rule_id: rule.rule_id,
    rule_family: rule.rule_family,
    frameworks: rule.frameworks,
  });
  const fw = fwResult.frameworks;

  const astDocs = fw.owasp_agentic
    .map((id) => AST_CATEGORIES.find((c) => c.id === id))
    .filter((c): c is (typeof AST_CATEGORIES)[0] => Boolean(c));

  const llmDocs = fw.owasp_llm
    .map((id) => getLlmCategoryDoc(id))
    .filter((c): c is (typeof LLM_CATEGORIES)[0] => Boolean(c));

  useEffect(() => {
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") closePopover();
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

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
          className="animate-popover-morph pointer-events-auto max-h-[calc(100vh-2rem)] w-full max-w-[36rem] overflow-y-auto rounded-xl border border-border-strong bg-card p-5 shadow-[0_28px_90px_rgba(0,0,0,0.5)] sm:max-h-[calc(100vh-3rem)] sm:p-6"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-full bg-accent px-2 py-0.5 font-mono text-[10px] text-accent-foreground">
                  {rule.rule_id}
                </span>
                <span className="text-xs text-muted-foreground">{rule.category}</span>
                {fwResult.isRetrospective && (
                  <span className="rounded-full bg-warning-bg px-2 py-0.5 text-[10px] text-warning border border-warning/20">
                    Retrospective v{fw.mapping_version}
                  </span>
                )}
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

          <div className="mt-5 space-y-4">
            <div className="rounded-xl bg-muted px-4 py-3.5">
              <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                Remediation
              </span>
              <p className="mt-1.5 text-sm leading-6 text-foreground">{rule.remediation}</p>
            </div>

            {/* Tier 1: OWASP Agentic Skills */}
            {astDocs.length > 0 && (
              <div className="rounded-xl border border-border bg-background/50 p-3.5">
                <span className="text-[11px] font-semibold uppercase tracking-wide text-accent">
                  1. Primary: OWASP Agentic Skills
                </span>
                <div className="mt-2 space-y-1.5">
                  {astDocs.map((c) => (
                    <div key={c.id} className="text-xs">
                      <span className="font-mono font-semibold text-foreground">{c.id}</span>{" "}
                      <span className="text-foreground/90">— {c.title}</span>
                      <p className="mt-0.5 text-muted-foreground">{c.summary}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tier 2: OWASP GenAI LLM */}
            {llmDocs.length > 0 && (
              <div className="rounded-xl border border-border bg-background/50 p-3.5">
                <span className="text-[11px] font-semibold uppercase tracking-wide text-accent">
                  2. Applied Mechanism: OWASP GenAI LLM (2026)
                </span>
                <div className="mt-2 space-y-2">
                  {llmDocs.map((c) => (
                    <div key={c.id} className="text-xs">
                      <span className="font-mono font-semibold text-foreground">{c.id}</span>{" "}
                      <span className="text-foreground/90">— {c.title}</span>
                      <p className="mt-0.5 text-muted-foreground">{c.summary}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tier 3: NIST AI Alignment */}
            {(fw.nist_gai_risks.length > 0 || fw.nist_rmf.length > 0) && (
              <div className="rounded-xl border border-border bg-background/50 p-3.5">
                <span className="text-[11px] font-semibold uppercase tracking-wide text-accent">
                  3. Alignment: NIST AI Frameworks
                </span>
                <div className="mt-2 space-y-2 text-xs">
                  {fw.nist_gai_risks.length > 0 && (
                    <div>
                      <span className="font-medium text-foreground">NIST AI 600-1 Risks:</span>{" "}
                      <span className="text-muted-foreground">{fw.nist_gai_risks.join(", ")}</span>
                    </div>
                  )}
                  {fw.nist_rmf.length > 0 && (
                    <div>
                      <span className="font-medium text-foreground">NIST AI RMF 1.0:</span>{" "}
                      <span className="font-mono text-accent">{fw.nist_rmf.join(", ")}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
