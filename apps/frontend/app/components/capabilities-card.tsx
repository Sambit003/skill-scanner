"use client";

import { useId, useMemo, useState } from "react";
import type { CapabilityResponse } from "@/app/lib/api";
import { ChevronDownIcon } from "@/app/components/icons";

type CapabilityGroup = {
  label: string;
  entries: CapabilityResponse[];
};

function groupByLabel(capabilities: CapabilityResponse[]): CapabilityGroup[] {
  const groups = new Map<string, CapabilityResponse[]>();
  for (const capability of capabilities) {
    const entries = groups.get(capability.label);
    if (entries) {
      entries.push(capability);
    } else {
      groups.set(capability.label, [capability]);
    }
  }
  return Array.from(groups, ([label, entries]) => ({ label, entries }));
}

function locationLabel(capability: CapabilityResponse): string {
  return `${capability.location.file}:${capability.location.start_line}`;
}

/**
 * "What this skill can do": behavior the scanner lists apart from findings,
 * such as running shell commands or reading environment variables. Hidden
 * when the scan has no entries or predates the list.
 */
export function CapabilitiesCard({ capabilities }: { capabilities: CapabilityResponse[] | null | undefined }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const groups = useMemo(() => groupByLabel(capabilities ?? []), [capabilities]);

  if (!capabilities || capabilities.length === 0) {
    return null;
  }

  return (
    <section className="mt-4 rounded-card border border-border bg-card">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-start gap-3 rounded-card px-4 py-3 text-left transition-colors duration-150 hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/25"
      >
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-medium text-foreground">What this skill can do</h2>
          <p className="mt-0.5 text-xs leading-5 text-muted-foreground">
            These are things the skill is able to do, not problems. They are not counted in the risk score.
          </p>
          {!open && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {groups.map((group) => (
                <span key={group.label} className="rounded-full bg-muted px-2.5 py-1 text-[11px] text-muted-foreground">
                  {group.label} · {group.entries.length}
                </span>
              ))}
            </div>
          )}
        </div>
        <span className="shrink-0 rounded-full bg-muted px-2.5 py-1 font-mono text-[11px] text-muted-foreground">
          {capabilities.length} {capabilities.length === 1 ? "entry" : "entries"}
        </span>
        <ChevronDownIcon
          className={`mt-1 h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-300 ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div id={panelId} className="animate-detail-in space-y-4 border-t border-border px-4 py-4">
          {groups.map((group) => (
            <div key={group.label}>
              <h3 className="text-xs font-medium text-foreground">
                {group.label} <span className="font-normal text-muted-foreground">({group.entries.length})</span>
              </h3>
              <ul className="mt-2 divide-y divide-border overflow-hidden rounded-xl border border-border">
                {group.entries.map((capability) => (
                  <li
                    key={`${capability.rule_id}-${locationLabel(capability)}`}
                    className="grid gap-1 px-3 py-2 sm:grid-cols-[minmax(12rem,26rem)_minmax(0,1fr)] sm:items-baseline sm:gap-4"
                  >
                    <span className="truncate font-mono text-xs text-foreground" title={locationLabel(capability)}>
                      {locationLabel(capability)}
                    </span>
                    <code className="truncate font-mono text-xs text-muted-foreground" title={capability.snippet ?? undefined}>
                      {capability.snippet || "—"}
                    </code>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
