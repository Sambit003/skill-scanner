"use client";

import { useEffect, useId, useRef, useState } from "react";
import { CheckIcon, ChevronDownIcon } from "@/app/components/icons";

interface CategoryFilterMenuProps {
  categories: string[];
  value: string;
  onChange: (value: string) => void;
}

export function CategoryFilterMenu({ categories, value, onChange }: CategoryFilterMenuProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const menuId = useId();
  const options = [
    { value: "ALL", label: "All categories" },
    ...categories.map((category) => ({ value: category, label: category })),
  ];
  const selectedLabel = options.find((option) => option.value === value)?.label ?? "All categories";

  useEffect(() => {
    if (!open) return;

    function handlePointerDown(event: MouseEvent | TouchEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
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

  function selectCategory(nextValue: string) {
    onChange(nextValue);
    setOpen(false);
  }

  return (
    <div ref={rootRef} className="relative w-44 shrink-0">
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((current) => !current)}
        className={`grid w-full grid-cols-[minmax(0,1fr)_1.25rem] items-center gap-2 rounded-full border bg-card py-1.5 pl-3.5 pr-2 text-left text-xs font-medium text-foreground outline-none transition-[border-color,box-shadow,background-color] duration-150 hover:bg-muted focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/25 ${
          open ? "border-accent ring-2 ring-accent/20" : "border-border"
        }`}
      >
        <span className="truncate">{selectedLabel}</span>
        <span className="flex h-5 w-5 items-center justify-center" aria-hidden="true">
          <ChevronDownIcon className={`h-3.5 w-3.5 transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
        </span>
      </button>

      {open && (
        <div
          id={menuId}
          role="listbox"
          aria-label="Filter findings by category"
          className="animate-popover-morph absolute right-0 top-[calc(100%+0.4rem)] z-40 max-h-64 w-max min-w-full max-w-72 origin-top-right overflow-y-auto rounded-lg border border-border bg-card p-1.5 shadow-[0_16px_40px_-18px_rgba(0,0,0,0.55)]"
        >
          {options.map((option) => {
            const selected = option.value === value;
            return (
              <button
                key={option.value}
                type="button"
                role="option"
                aria-selected={selected}
                onClick={() => selectCategory(option.value)}
                className={`grid w-full grid-cols-[1rem_minmax(0,1fr)] items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs transition-colors duration-150 ${
                  selected ? "bg-muted text-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                <span className="flex h-4 w-4 items-center justify-center">
                  {selected && <CheckIcon className="h-3.5 w-3.5 text-accent" />}
                </span>
                <span className="whitespace-nowrap">{option.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
