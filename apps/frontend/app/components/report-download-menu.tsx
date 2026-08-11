"use client";

import { useEffect, useRef, useState } from "react";
import { reportUrl, type ReportFormat } from "@/app/lib/api";
import { ChevronDownIcon, DownloadIcon } from "@/app/components/icons";

const REPORT_LABELS: Record<ReportFormat, string> = {
  json: "JSON",
  markdown: "Markdown",
  sarif: "SARIF",
  terminal: "Text",
};

export function ReportDownloadMenu({
  scanId,
  formats,
  dark = false,
  align = "right",
}: {
  scanId: string;
  formats: ReportFormat[];
  dark?: boolean;
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const uniqueFormats = Array.from(new Set(formats));

  useEffect(() => {
    function handlePointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleEscape);
    };
  }, []);

  if (uniqueFormats.length === 0) return null;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className={`flex items-center gap-1.5 rounded-full px-4 py-2 text-xs font-medium transition-colors duration-150 ${
          dark
            ? "bg-foreground text-background hover:opacity-90"
            : "border border-border bg-card text-foreground hover:border-border-strong hover:bg-muted"
        }`}
      >
        <DownloadIcon className="h-3.5 w-3.5" />
        Download report
        <ChevronDownIcon className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div
          className={`absolute z-20 mt-2 min-w-44 overflow-hidden rounded-2xl border border-border bg-card shadow-[0_12px_32px_-16px_rgba(28,26,23,0.25)] ${
            align === "right" ? "right-0" : "left-0"
          }`}
        >
          {uniqueFormats.map((format) => (
            <a
              key={format}
              href={reportUrl(scanId, format)}
              download
              onClick={() => setOpen(false)}
              className="flex items-center justify-between gap-4 px-4 py-3 text-sm text-foreground transition-colors duration-150 hover:bg-muted"
            >
              <span>{REPORT_LABELS[format]}</span>
              <span className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
                {format}
              </span>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
