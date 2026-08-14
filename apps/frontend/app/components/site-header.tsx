import Link from "next/link";

interface SiteHeaderProps {
  actionHref?: string;
  actionLabel?: string;
}

export function SiteHeader({ actionHref, actionLabel }: SiteHeaderProps) {
  return (
    <header className="sticky top-0 z-20 border-b border-border/70 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex w-full max-w-[92rem] items-center justify-between px-6 py-4">
        <Link href="/" className="font-display text-[17px] font-semibold tracking-tight text-foreground">
          AI <span className="text-accent">Skill Scanner</span>
        </Link>
        <div className="flex items-center gap-3">
          <Link
            href="/scans"
            className="text-xs font-medium text-muted-foreground transition-colors duration-150 hover:text-foreground sm:text-sm"
          >
            Scans
          </Link>
          <Link
            href="/framework"
            className="text-xs font-medium text-muted-foreground transition-colors duration-150 hover:text-foreground sm:text-sm"
          >
            Documentation
          </Link>
          {actionHref && actionLabel ? (
            <Link
              href={actionHref}
              className="rounded-full bg-accent px-4 py-2 text-xs font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover sm:text-sm"
            >
              {actionLabel}
            </Link>
          ) : null}
        </div>
      </div>
    </header>
  );
}
