export const severities = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof severities)[number];

export interface Finding {
  id: string;
  code: string;
  type: string;
  severity: Severity;
  url: string;
  details: string;
  confidence: string;
  severity_reason: string;
  fix_steps: string[];
  verification: string;
  reference: string;
}

export interface ScanReport {
  schema_version: 2;
  target: string;
  generated_at: string;
  mode: "passive" | "source";
  complete: boolean;
  vulnerabilities: Finding[];
  scanned_urls: string[];
  attempted_urls: number;
  requests_made: number;
  duration_seconds: number;
  summary: Record<Severity, number>;
  warnings: { code: string; url: string; message: string }[];
  url_limit_exceeded: boolean;
  time_limit_exceeded: boolean;
  request_limit_exceeded: boolean;
  message: string;
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

export function isScanReport(value: unknown): value is ScanReport {
  if (!object(value) || value.schema_version !== 2 || !["passive", "source"].includes(String(value.mode))) return false;
  if (!["target", "generated_at", "message"].every((key) => typeof value[key] === "string")) return false;
  if (!["complete", "url_limit_exceeded", "time_limit_exceeded", "request_limit_exceeded"].every((key) => typeof value[key] === "boolean")) return false;
  if (!["attempted_urls", "requests_made", "duration_seconds"].every((key) => typeof value[key] === "number" && Number.isFinite(value[key]) && (value[key] as number) >= 0)) return false;
  if (!strings(value.scanned_urls) || value.scanned_urls.length > 2000 || !object(value.summary)) return false;
  const summary = value.summary;
  if (!severities.every((severity) => typeof summary[severity] === "number" && Number.isInteger(summary[severity]) && (summary[severity] as number) >= 0)) return false;
  if (!Array.isArray(value.warnings) || value.warnings.length > 100 || !value.warnings.every((warning: unknown) => object(warning) && ["code", "url", "message"].every((key) => typeof warning[key] === "string"))) return false;
  if (!Array.isArray(value.vulnerabilities) || value.vulnerabilities.length > 500) return false;
  return value.vulnerabilities.every((finding: unknown) => object(finding) &&
    ["id", "code", "type", "url", "details", "confidence", "severity_reason", "verification", "reference"].every((key) => typeof finding[key] === "string") &&
    severities.some((severity) => severity === finding.severity) && strings(finding.fix_steps));
}

export function filterFindings(findings: Finding[], severity: string, search: string) {
  const query = search.trim().toLowerCase();
  return findings.filter((finding) => (severity === "all" || finding.severity === severity) &&
    `${finding.type} ${finding.url} ${finding.code}`.toLowerCase().includes(query));
}

export function trustedReference(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (url.protocol === "https:" && url.hostname === "cheatsheetseries.owasp.org") return url.href;
  } catch { /* Omit malformed references. */ }
  return undefined;
}

export function reportFilename(report: ScanReport) {
  return `website-threat-scan-${report.generated_at.slice(0, 10).replace(/[^0-9-]/g, "")}.json`;
}
