import { ScanResultsSection } from "@/app/components/scan-results-section";
import { SiteHeader } from "@/app/components/site-header";

export default function ScansIndexPage() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader />
      <main className="flex-1">
        <ScanResultsSection />
      </main>
    </div>
  );
}
