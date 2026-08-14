const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type ReportFormat = "json" | "markdown" | "sarif" | "terminal";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "canceled";

export interface CreateScanResponse {
  scan_id: string;
  status: ScanStatus;
  mode: string;
  created_at: string;
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
    throw new ApiError(`Couldn't reach the scanner API at ${API_BASE}. Make sure the backend is running.`);
  }

  if (!res.ok) {
    throw new ApiError(await parseErrorDetail(res), res.status);
  }
  return res.json();
}

export async function createScan(target: string): Promise<CreateScanResponse> {
  return requestJson<CreateScanResponse>("/v1/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      asset_type: "agent_skill",
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
  const page = params?.page ?? 1;
  const pageSize = params?.pageSize ?? 50;
  search.set("limit", String(pageSize));
  search.set("offset", String((page - 1) * pageSize));
  if (params?.status) search.set("status", params.status);
  if (params?.severity) search.set("severity", params.severity);
  if (params?.target) search.set("target", params.target);
  if (params?.scanId) search.set("scan_id", params.scanId);
  if (params?.sort) search.set("sort", params.sort);

  const suffix = search.size ? `?${search.toString()}` : "";
  const response = await requestJson<ScanListResponse | ScanStatusResponse[]>(`/v1/scans${suffix}`);
  if (!Array.isArray(response)) return response;

  return {
    page,
    page_size: pageSize,
    total: response.length,
    items: response,
  };
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
  rule_id: string;
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
