"use client";

import { useEffect, useId, useRef, useState } from "react";

import { InfoIcon } from "@/app/components/icons";

type InfoPopoverProps = {
  title: string;
  description: string;
  remediation?: string;
  meta?: string;
  align?: "left" | "center" | "right";
};

export function InfoPopover({
  title,
  description,
  remediation,
  meta,
  align = "left",
}: InfoPopoverProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLSpanElement | null>(null);
  const popoverId = useId();

  useEffect(() => {
    if (!open) return;

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
  }, [open]);

  return (
    <span
      ref={rootRef}
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        aria-label={`More info about ${title}`}
        aria-expanded={open}
        aria-controls={popoverId}
        onClick={() => setOpen((current) => !current)}
        className="inline-flex h-[18px] w-[18px] items-center justify-center rounded-full border border-border bg-background text-muted-foreground transition-colors duration-150 hover:border-border-strong hover:text-foreground focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
      >
        <InfoIcon className="h-3 w-3" />
      </button>

      {open && (
        <div
          id={popoverId}
          role="dialog"
          aria-label={title}
          className={`absolute top-6 z-30 w-72 rounded-2xl border border-border bg-card p-3 text-left font-sans font-normal tracking-normal shadow-[0_14px_40px_rgba(0,0,0,0.08)] ${
            align === "right"
              ? "right-0"
              : align === "center"
                ? "left-1/2 -translate-x-1/2"
                : "left-0"
          }`}
        >
          <div className="space-y-2">
            <div>
              <p className="text-sm font-medium text-foreground">{title}</p>
              {meta ? (
                <p className="mt-0.5 text-[11px] uppercase tracking-wide text-muted-foreground">{meta}</p>
              ) : null}
            </div>
            <p className="text-xs leading-5 text-muted-foreground">{description}</p>
            {remediation ? (
              <p className="rounded-xl bg-muted px-2.5 py-2 text-xs leading-5 text-foreground">{remediation}</p>
            ) : null}
          </div>
        </div>
      )}
    </span>
  );
}
