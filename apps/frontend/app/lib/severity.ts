export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-danger-bg text-danger",
  HIGH: "bg-high-bg text-high",
  MEDIUM: "bg-warning-bg text-warning",
  LOW: "bg-success-bg text-success",
};

export const SEVERITY_BAR_COLOR: Record<string, string> = {
  CRITICAL: "bg-danger",
  HIGH: "bg-high",
  MEDIUM: "bg-warning",
  LOW: "bg-success",
};

export const RECOMMENDATION_STYLES: Record<string, string> = {
  SAFE: "bg-success-bg text-success",
  CAUTION: "bg-warning-bg text-warning",
  DO_NOT_INSTALL: "bg-danger-bg text-danger",
};

export function formatRecommendation(recommendation: string): string {
  return recommendation.replaceAll("_", " ");
}

export function formatDuration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt || !completedAt) return "—";
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const totalSeconds = Math.round(ms / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${seconds}s`;
}
