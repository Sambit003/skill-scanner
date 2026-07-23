const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type ReportFormat = "json" | "markdown" | "sarif" | "terminal";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "canceled";

export interface CreateScanResponse {
  scan_id: string;
  status: ScanStatus;
  mode: string;
  created_at: string;
  agent_review_enabled: boolean;
  agent_review_provider: string | null;
}

export interface BreakdownItemResponse {
  label: string;
  count: number;
}

export interface ReportLinkResponse {
  format: ReportFormat;
  url: string;
}

export interface ScanLinksResponse {
  self: string;
  findings: string;
  reports: string;
  events: string;
  share_summary: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  target: string;
  display_target: string | null;
  mode: string;
  status: ScanStatus;
  requested_formats: ReportFormat[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  duration_ms: number | null;
  is_terminal: boolean;
  next_poll_after_ms: number;
  error: string | null;
  risk_score: number | null;
  severity: string | null;
  recommendation: string | null;
  safe_to_install: boolean | null;
  primary_verdict: string | null;
  headline: string | null;
  summary: string | null;
  findings_count: number | null;
  findings_by_severity: Record<string, number>;
  findings_by_category: Record<string, number>;
  severity_breakdown: BreakdownItemResponse[];
  category_breakdown: BreakdownItemResponse[];
  available_reports: ReportFormat[];
  report_downloads: ReportLinkResponse[];
  links: ScanLinksResponse | null;
  scanner_version: string | null;
  scan_mode: string | null;
  llm_requested: boolean;
  llm_used: boolean;
  agent_review_provider: string | null;
  agent_review_model: string | null;
  agent_review_requested: boolean;
  agent_review_used: boolean;
  agent_review_status: string | null;
  agent_review_verdict: string | null;
  agent_review_summary: string | null;
}

export interface ScanListResponse {
  page: number;
  page_size: number;
  total: number;
  items: ScanStatusResponse[];
}

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

async function parseErrorDetail(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    // response wasn't JSON, fall through to the generic message
  }
  return `Request failed with status ${res.status}`;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(`Couldn't reach the SkillSpector API at ${API_BASE}. Make sure the backend is running.`);
  }

  if (!res.ok) {
    throw new ApiError(await parseErrorDetail(res), res.status);
  }
  return res.json();
}

export interface CreateScanOptions {
  agentReviewEnabled?: boolean;
  agentReviewProvider?: "openrouter";
  agentReviewModel?: string;
  agentReviewApiKey?: string;
}

export async function createScan(target: string, options?: CreateScanOptions): Promise<CreateScanResponse> {
  return requestJson<CreateScanResponse>("/v1/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      mode: "deterministic",
      formats: ["json", "markdown", "sarif", "terminal"],
      agent_review_enabled: options?.agentReviewEnabled ?? false,
      agent_review_provider: options?.agentReviewProvider ?? null,
      agent_review_model: options?.agentReviewModel ?? null,
      agent_review_api_key: options?.agentReviewApiKey ?? null,
    }),
  });
}

export async function listScans(params?: {
  page?: number;
  pageSize?: number;
  status?: string;
  severity?: string;
  target?: string;
  scanId?: string;
  sort?: string;
}): Promise<ScanListResponse> {
  const search = new URLSearchParams();
  if (params?.page) search.set("page", String(params.page));
  if (params?.pageSize) search.set("page_size", String(params.pageSize));
  if (params?.status) search.set("status", params.status);
  if (params?.severity) search.set("severity", params.severity);
  if (params?.target) search.set("target", params.target);
  if (params?.scanId) search.set("scan_id", params.scanId);
  if (params?.sort) search.set("sort", params.sort);

  const suffix = search.size ? `?${search.toString()}` : "";
  return requestJson<ScanListResponse>(`/v1/scans${suffix}`);
}

export async function getScan(scanId: string): Promise<ScanStatusResponse> {
  return requestJson<ScanStatusResponse>(`/v1/scans/${scanId}`);
}

export interface FindingLocation {
  file: string;
  start_line: number;
  end_line: number | null;
}

export interface FindingResponse {
  id: string;
  title: string | null;
  rule_family: string | null;
  category: string | null;
  pattern: string | null;
  severity: string;
  confidence: number;
  location: FindingLocation;
  file_path_display: string | null;
  finding: string | null;
  explanation: string | null;
  remediation: string | null;
  code_snippet: string | null;
  intent: string | null;
  documentation_url: string | null;
  tags: string[];
}

export interface ScanFindingsResponse {
  scan_id: string;
  status: ScanStatus;
  total: number;
  page: number;
  page_size: number;
  findings: FindingResponse[];
}

export async function getScanFindings(
  scanId: string,
  params?: {
    severity?: string;
    category?: string;
    ruleFamily?: string;
    file?: string;
    q?: string;
    page?: number;
    pageSize?: number;
    sort?: string;
  }
): Promise<ScanFindingsResponse> {
  const search = new URLSearchParams();
  if (params?.severity) search.set("severity", params.severity);
  if (params?.category) search.set("category", params.category);
  if (params?.ruleFamily) search.set("rule_family", params.ruleFamily);
  if (params?.file) search.set("file", params.file);
  if (params?.q) search.set("q", params.q);
  if (params?.page) search.set("page", String(params.page));
  if (params?.pageSize) search.set("page_size", String(params.pageSize));
  if (params?.sort) search.set("sort", params.sort);

  const suffix = search.size ? `?${search.toString()}` : "";
  return requestJson<ScanFindingsResponse>(`/v1/scans/${scanId}/findings${suffix}`);
}

export interface ScanReportsManifestResponse {
  scan_id: string;
  reports: ReportLinkResponse[];
}

export async function getScanReports(scanId: string): Promise<ScanReportsManifestResponse> {
  return requestJson<ScanReportsManifestResponse>(`/v1/scans/${scanId}/reports`);
}

export interface ScanEventResponse {
  id: number;
  scan_id: string;
  status: ScanStatus;
  message: string;
  created_at: string;
}

export interface ScanEventsResponse {
  scan_id: string;
  events: ScanEventResponse[];
}

export async function getScanEvents(scanId: string): Promise<ScanEventsResponse> {
  return requestJson<ScanEventsResponse>(`/v1/scans/${scanId}/events`);
}

export interface ScanShareSummaryResponse {
  scan_id: string;
  headline: string | null;
  summary: string | null;
  risk_score: number | null;
  severity: string | null;
  recommendation: string | null;
  target: string;
  findings_preview: FindingResponse[];
}

export async function getScanShareSummary(scanId: string): Promise<ScanShareSummaryResponse> {
  return requestJson<ScanShareSummaryResponse>(`/v1/scans/${scanId}/share-summary`);
}

export interface AgentReviewFindingResponse {
  finding_key: string;
  disposition: "keep" | "likely_false_positive" | "likely_duplicate" | "needs_human_review";
  rationale: string;
  confidence: number;
}

export interface AgentReviewStructuredReportResponse {
  overall_verdict: "confirm_safe" | "confirm_unsafe" | "mixed_signal" | "needs_human_review" | "cautionary";
  executive_summary: string;
  top_confirmed_risks: string[];
  likely_false_positives: AgentReviewFindingResponse[];
  likely_duplicates: AgentReviewFindingResponse[];
  follow_up_actions: string[];
  review_confidence: number;
}

export interface AgentReviewReportResponse {
  scan_id: string;
  requested: boolean;
  used: boolean;
  status: string | null;
  verdict: string | null;
  summary: string | null;
  report: AgentReviewStructuredReportResponse | null;
}

export async function getScanAgentReview(scanId: string): Promise<AgentReviewReportResponse> {
  return requestJson<AgentReviewReportResponse>(`/v1/scans/${scanId}/agent-review`);
}

export interface OpenRouterModelResponse {
  id: string;
  name: string;
  description: string | null;
  context_length: number | null;
  max_completion_tokens: number | null;
  modality: string | null;
  prompt_price: string | null;
  completion_price: string | null;
  supported_parameters: string[];
}

export interface OpenRouterModelsResponse {
  source: string;
  fetched_at: number;
  total_count: number;
  items: OpenRouterModelResponse[];
}

export async function listOpenRouterModels(refresh = false): Promise<OpenRouterModelsResponse> {
  const suffix = refresh ? "?refresh=true" : "";
  return requestJson<OpenRouterModelsResponse>(`/v1/providers/openrouter/models${suffix}`);
}

export interface RuleDocResponse {
  rule_id: string;
  rule_family: string;
  title: string;
  category: string;
  description: string;
  remediation: string;
  documentation_url: string;
}

export interface RuleListResponse {
  items: RuleDocResponse[];
}

export async function listRules(): Promise<RuleListResponse> {
  return requestJson<RuleListResponse>("/v1/rules");
}

export async function getRule(ruleId: string): Promise<RuleDocResponse> {
  return requestJson<RuleDocResponse>(`/v1/rules/${ruleId}`);
}

export function reportUrl(scanId: string, format: ReportFormat): string {
  return `${API_BASE}/v1/scans/${scanId}/reports/${format}`;
}
