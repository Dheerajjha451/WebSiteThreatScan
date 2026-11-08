import test from "node:test";
import assert from "node:assert/strict";
import { filterFindings, isScanReport, reportFilename, trustedReference } from "../lib/report.ts";

const finding = {
  id: "test", code: "headers.csp", type: "Missing enforced CSP", severity: "medium", url: "https://example.com/",
  details: "No enforced header.", confidence: "high", severity_reason: "Medium: defense in depth is missing.",
  fix_steps: ["Test a policy", "Enforce the policy"], verification: "Rescan", reference: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
};
const report = {
  schema_version: 2, mode: "passive", target: "https://example.com/", generated_at: "2026-11-08T12:00:00Z",
  complete: true, vulnerabilities: [finding], scanned_urls: ["https://example.com/"], attempted_urls: 1,
  requests_made: 1, duration_seconds: .5, summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
  warnings: [], url_limit_exceeded: false, time_limit_exceeded: false, request_limit_exceeded: false, message: "Done",
};

test("validates complete passive and source reports", () => {
  assert.equal(isScanReport(report), true);
  assert.equal(isScanReport({ ...report, mode: "source", complete: false }), true);
});

test("rejects malformed or incompatible reports before rendering", () => {
  for (const input of [null, {}, { ...report, schema_version: 1 }, { ...report, vulnerabilities: [{}] },
    { ...report, vulnerabilities: [{ ...finding, fix_steps: "not an array" }] },
    { ...report, vulnerabilities: [{ ...finding, severity: "urgent" }] },
    { ...report, summary: {} }, { ...report, warnings: [null] }, { ...report, duration_seconds: -1 }]) {
    assert.equal(isScanReport(input), false);
  }
});

test("filters by severity, issue, code and page without altering the source", () => {
  const findings = [finding, { ...finding, id: "two", severity: "high", type: "Password form", code: "forms.password", url: "https://example.com/login" }];
  assert.equal(filterFindings(findings, "high", " LOGIN ").length, 1);
  assert.equal(filterFindings(findings, "all", "headers.csp").length, 1);
  assert.equal(filterFindings(findings, "low", "").length, 0);
  assert.equal(findings.length, 2);
});

test("untrusted imported links cannot become executable references", () => {
  for (const value of ["javascript:alert(1)", "https://cheatsheetseries.owasp.org.evil.example/a", "http://cheatsheetseries.owasp.org", "not a url"]) {
    assert.equal(trustedReference(value), undefined);
  }
  assert.equal(trustedReference(finding.reference), finding.reference);
});

test("export filenames cannot inject paths", () => {
  assert.equal(reportFilename(report), "website-threat-scan-2026-11-08.json");
  assert.equal(reportFilename({ ...report, generated_at: "../../bad" }).includes("/"), false);
});
