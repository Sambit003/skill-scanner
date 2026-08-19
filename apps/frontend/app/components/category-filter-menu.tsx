"use client";

import { useEffect, useId, useRef, useState } from "react";
import { ChevronDownIcon } from "@/app/components/icons";

interface CategoryFilterMenuProps {
  categories: string[];
  value: string;
  onChange: (value: string) => void;
}

export function CategoryFilterMenu({ categories, value, onChange }: CategoryFilterMenuProps) {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const menuId = useId();
  const options = [
    { value: "ALL", label: "All categories" },
    ...categories.map((category) => ({ value: category, label: category })),
  ];
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === value));
  const selectedLabel = options.find((option) => option.value === value)?.label ?? "All categories";

  useEffect(() => {
    if (!open) return;

    function handlePointerDown(event: MouseEvent | TouchEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      setOpen(false);
      triggerRef.current?.focus();
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

  function openMenu(focusOption = false) {
    setActiveIndex(selectedIndex);
    setOpen(true);
    requestAnimationFrame(() => {
      optionRefs.current[selectedIndex]?.scrollIntoView({ block: "nearest" });
      if (focusOption) optionRefs.current[selectedIndex]?.focus();
    });
  }

  function selectCategory(nextValue: string) {
    onChange(nextValue);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function moveOption(nextIndex: number) {
    const normalizedIndex = (nextIndex + options.length) % options.length;
    setActiveIndex(normalizedIndex);
    optionRefs.current[normalizedIndex]?.focus();
  }

  return (
    <div ref={rootRef} className="relative h-7 w-44 shrink-0">
      <div
        className={`absolute right-0 top-0 z-40 grid overflow-hidden border bg-card transition-[width,grid-template-rows,border-color,border-radius,box-shadow] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] ${
          open
            ? "w-60 max-w-[calc(100vw-2rem)] grid-rows-[1.75rem_1fr] rounded-xl border-accent shadow-[0_18px_44px_-18px_rgba(0,0,0,0.55)]"
            : "w-44 grid-rows-[1.75rem_0fr] rounded-[14px] border-border shadow-none"
        }`}
      >
        <button
          ref={triggerRef}
          type="button"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={menuId}
          onClick={() => open ? setOpen(false) : openMenu()}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
              event.preventDefault();
              openMenu(true);
            }
          }}
          className={`grid min-h-7 w-full grid-cols-[minmax(0,1fr)_1.25rem] items-center gap-2 px-2 pl-3.5 text-left text-xs font-medium text-foreground outline-none transition-colors duration-150 hover:bg-muted focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/25 ${open ? "bg-muted/50" : "bg-card"}`}
        >
          <span className="truncate">{selectedLabel}</span>
          <span className="flex h-5 w-5 items-center justify-center" aria-hidden="true">
            <ChevronDownIcon className={`h-3.5 w-3.5 transition-transform duration-300 ${open ? "rotate-180" : ""}`} />
          </span>
        </button>

        <div className="min-h-0 overflow-hidden">
          <div
            id={menuId}
            role="listbox"
            aria-label="Filter findings by category"
            aria-hidden={!open}
            className={`max-h-56 overflow-y-auto border-t border-border p-1 transition-[opacity,transform] duration-200 ${
              open
                ? "visible translate-y-0 opacity-100 delay-75"
                : "invisible -translate-y-1 opacity-0 delay-0"
            }`}
          >
            {options.map((option, index) => {
              const selected = option.value === value;
              return (
                <button
                  key={option.value}
                  ref={(node) => { optionRefs.current[index] = node; }}
                  type="button"
                  role="option"
                  aria-selected={selected}
                  tabIndex={open && index === activeIndex ? 0 : -1}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => selectCategory(option.value)}
                  onKeyDown={(event) => {
                    if (event.key === "ArrowDown") {
                      event.preventDefault();
                      moveOption(activeIndex + 1);
                    } else if (event.key === "ArrowUp") {
                      event.preventDefault();
                      moveOption(activeIndex - 1);
                    } else if (event.key === "Home") {
                      event.preventDefault();
                      moveOption(0);
                    } else if (event.key === "End") {
                      event.preventDefault();
                      moveOption(options.length - 1);
                    } else if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      selectCategory(option.value);
                    }
                  }}
                  className={`relative block w-full rounded-md px-3.5 py-1.5 text-left text-xs outline-none transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/25 ${
                    selected ? "bg-muted font-medium text-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:bg-muted focus-visible:text-foreground"
                  }`}
                >
                  {selected && <span aria-hidden="true" className="absolute bottom-1.5 left-1.5 top-1.5 w-0.5 rounded-full bg-accent" />}
                  <span className="whitespace-nowrap">{option.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
