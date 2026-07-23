import { ScanConsole } from "@/app/components/scan-console";
import { SiteHeader } from "@/app/components/site-header";

type CardSize = "lg" | "wide" | "sm";

const CATEGORIES: { title: string; detail: string; size: CardSize }[] = [
  {
    title: "Prompt injection",
    detail:
      "Override instructions, hidden directives, and exfiltration-framed steering — the eight patterns that hijack a skill's behavior before it ever runs.",
    size: "lg",
  },
  { title: "Data exfiltration", detail: "Env harvesting, file enumeration, external transmission", size: "sm" },
  { title: "Privilege escalation", detail: "Sudo, credential access, container escape", size: "sm" },
  { title: "Supply chain", detail: "Unpinned deps, typosquats, known CVEs, obfuscation", size: "sm" },
  { title: "Excessive agency", detail: "Unrestricted tools, scope creep, unbounded resources", size: "sm" },
  {
    title: "Dangerous execution",
    detail: "exec/eval, subprocess, and taint-tracked data flow from untrusted input to a dangerous sink",
    size: "wide",
  },
  { title: "Malware signatures", detail: "YARA-matched webshells, miners, and exploit tooling", size: "sm" },
  { title: "MCP hygiene", detail: "Least privilege, tool poisoning, rug-pull signals", size: "sm" },
];

const SPAN_CLASSES: Record<CardSize, string> = {
  lg: "sm:col-span-2 sm:row-span-2",
  wide: "sm:col-span-2 sm:row-span-1",
  sm: "sm:col-span-1 sm:row-span-1",
};

const REPORT_FORMATS = ["JSON", "Markdown", "SARIF", "Terminal"];

export default function Home() {
  return (
    <div className="flex flex-1 flex-col bg-background">
      <SiteHeader />

      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col items-center px-6 pt-6 sm:pt-8">
        <div className="mb-10 flex flex-col items-center text-center sm:mb-12">
          <h1 className="max-w-3xl font-display text-4xl font-semibold leading-tight tracking-tight text-foreground sm:text-5xl sm:leading-[1.12] md:text-6xl">
            <span className="animate-fade-up block" style={{ animationDelay: "60ms" }}>
              Know what an AI skill
            </span>
            <span className="animate-fade-up block" style={{ animationDelay: "200ms" }}>
              actually does before you install it.
            </span>
          </h1>
          <p
            className="animate-fade-up mt-5 max-w-md text-base text-muted-foreground"
            style={{ animationDelay: "340ms" }}
          >
            Deterministic by default. No code execution.
          </p>
        </div>

        <ScanConsole />
      </main>

      <section
        id="coverage"
        className="flex w-full scroll-mt-20 flex-col justify-center py-16 sm:min-h-screen sm:py-24"
      >
        <div className="px-6 text-center">
          <h2 className="font-display text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            What gets checked
          </h2>
          <p className="mx-auto mt-2 max-w-md text-muted-foreground">
            Nineteen deterministic rule families, run the same way every time.
          </p>
        </div>
        <div className="mt-10 grid flex-1 grid-cols-1 gap-3 px-6 sm:mt-14 sm:grid-cols-4 sm:grid-flow-dense sm:px-10 sm:[grid-auto-rows:minmax(140px,1fr)] lg:px-16">
          {CATEGORIES.map((category) => (
            <div
              key={category.title}
              className={`flex flex-col justify-center rounded-card border border-border bg-card p-5 transition-colors duration-150 hover:border-border-strong ${SPAN_CLASSES[category.size]} ${
                category.size === "lg" ? "sm:p-8" : "sm:p-6"
              }`}
            >
              <h3
                className={`font-medium text-foreground ${
                  category.size === "lg" ? "text-lg sm:text-xl" : "text-sm sm:text-base"
                }`}
              >
                {category.title}
              </h3>
              <p
                className={`mt-2 leading-6 text-muted-foreground ${
                  category.size === "lg" ? "text-sm sm:text-base sm:leading-7" : "text-sm"
                }`}
              >
                {category.detail}
              </p>
            </div>
          ))}
        </div>
      </section>

      <footer className="border-t border-border">
        <div className="mx-auto flex w-full max-w-5xl flex-col items-center gap-4 px-6 py-8 text-sm text-muted-foreground sm:flex-row sm:justify-between">
          <span>Reports export as {REPORT_FORMATS.join(" · ")}.</span>
          <span>BYOK keys are used per scan and never stored.</span>
        </div>
      </footer>
    </div>
  );
}
