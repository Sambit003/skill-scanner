import Link from "next/link";

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-20 border-b border-border/70 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex w-full max-w-5xl items-center justify-between px-6 py-4">
        <Link href="/" className="font-display text-[17px] font-semibold tracking-tight text-foreground">
          SuperAlign <span className="text-accent">Skill Scanner</span>
        </Link>
        <nav className="flex items-center gap-8 text-sm font-medium text-muted-foreground">
          <Link href="/scans" className="transition-colors duration-150 hover:text-foreground">
            Scans
          </Link>
        </nav>
      </div>
    </header>
  );
}
