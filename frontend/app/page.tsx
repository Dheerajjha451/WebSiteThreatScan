"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { filterFindings, isScanReport, reportFilename, severities, trustedReference, type Finding, type ScanReport } from "@/lib/report";

function FindingCard({ finding }: { finding: Finding }) {
  const reference = trustedReference(finding.reference);
  return (
    <details className={`finding finding-${finding.severity}`}>
      <summary>
        <span className={`badge badge-${finding.severity}`}>{finding.severity === "info" ? "Info" : finding.severity}</span>
        <span className="finding-title">{finding.type}<small>{finding.url}</small></span>
        <span className="details-hint"><span aria-hidden="true">ⓘ</span><span className="hint-label"> Why &amp; how to fix</span><span className="chevron" aria-hidden="true">⌄</span></span>
      </summary>
      <div className="finding-details">
        <section><h4>Why this severity?</h4><p>{finding.severity_reason}</p><span className="confidence">Detection confidence: {finding.confidence}. Severity describes potential impact; confidence describes certainty.</span></section>
        <section><h4>What we observed</h4><p>{finding.details}</p><code>{finding.code}</code></section>
        <section><h4>Steps you can take</h4><ol>{finding.fix_steps.map((step, index) => <li key={index}>{step}</li>)}</ol></section>
        <section><h4>Verify the fix</h4><p>{finding.verification}</p><p>Run the scan again after deploying the change.</p></section>
        {reference ? <a className="reference" href={reference} target="_blank" rel="noopener noreferrer">Read the OWASP guidance ↗</a> : null}
      </div>
    </details>
  );
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [maxUrls, setMaxUrls] = useState(10);
  const [maxDepth, setMaxDepth] = useState(2);
  const [results, setResults] = useState<ScanReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");
  const controller = useRef<AbortController | null>(null);
  const resultHeading = useRef<HTMLHeadingElement | null>(null);
  const importInput = useRef<HTMLInputElement | null>(null);
  useEffect(() => () => controller.current?.abort(), []);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (controller.current) return;
    try {
      const target = new URL(url.trim());
      if (!["https:", "http:"].includes(target.protocol) || target.username || target.password) throw new Error();
    } catch {
      setError("Enter a full HTTP or HTTPS URL without embedded credentials.");
      return;
    }
    if (!authorized) { setError("Confirm permission to scan this website."); return; }
    const active = new AbortController();
    controller.current = active;
    const timer = window.setTimeout(() => active.abort("timeout"), 65_000);
    setLoading(true);
    setError("");
    setResults(null);
    setSearch("");
    setSeverity("all");
    try {
      const response = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), authorized, max_urls: maxUrls, max_depth: maxDepth }),
        signal: active.signal,
      });
      const data: unknown = await response.json();
      if (isScanReport(data)) {
        setResults(data);
        if (!response.ok) setError("No pages could be analyzed. Expand scan coverage for the reasons.");
        window.requestAnimationFrame(() => resultHeading.current?.focus());
      } else if (!response.ok && typeof data === "object" && data !== null && "error" in data && typeof data.error === "string") {
        throw new Error(data.error);
      } else { throw new Error("The service returned an invalid report. Please try again."); }
    } catch (cause) {
      if (active.signal.aborted) {
        setError(active.signal.reason === "timeout" ? "The scan request timed out. Try a smaller page limit." : "Stopped waiting. The server may finish its bounded scan in the background.");
      } else { setError(cause instanceof Error ? cause.message : "The scan could not be completed."); }
    } finally {
      window.clearTimeout(timer);
      controller.current = null;
      setLoading(false);
    }
  }

  function exportReport() {
    if (!results) return;
    const blobUrl = URL.createObjectURL(new Blob([JSON.stringify(results, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = reportFilename(results);
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  }

  async function importReport(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > 2_097_152) { setError("Reports must be no larger than 2 MiB."); return; }
    try {
      const report: unknown = JSON.parse(await file.text());
      if (!isScanReport(report)) throw new Error("Choose a valid WebsiteThreatScan v2 JSON report.");
      setResults(report);
      setSearch("");
      setSeverity("all");
      setError("");
      window.requestAnimationFrame(() => resultHeading.current?.focus());
    } catch (cause) {
      setError(cause instanceof SyntaxError ? "This file is not valid JSON." : cause instanceof Error ? cause.message : "The report could not be opened.");
    }
  }

  const visible = results ? filterFindings(results.vulnerabilities, severity, search) : [];
  return (
    <main>
      <a className="skip-link" href="#scan-form">Skip to scanner</a>
      <div className="shell">
        <header className="site-header"><Link className="brand" href="/">◇ <span>WebsiteThreatScan</span></Link><span className="status"><span aria-hidden="true">●</span> Passive security review</span></header>
        <section className="intro" aria-labelledby="page-heading">
          <p className="eyebrow">Understand the risk. Know the next step.</p>
          <h1 id="page-heading">A clearer view of your<br className="desktop-break" /> website’s security.</h1>
          <p className="intro-copy">Find security gaps in public pages, understand their impact, and get practical steps to fix them.</p>
          <div className="capabilities"><span>HTTPS &amp; headers</span><span>Cookies &amp; forms</span><span>Exposed secrets</span><span>Mixed content</span></div>
        </section>
        <form id="scan-form" className="panel scan-form" onSubmit={handleSubmit} aria-busy={loading}>
          <label className="field-label" htmlFor="target-url">Website URL</label>
          <div className="url-row"><input id="target-url" type="url" autoComplete="url" placeholder="https://your-website.com" value={url} onChange={(event) => setUrl(event.target.value)} maxLength={2048} required disabled={loading} aria-describedby="url-help" /><button className="primary" type="submit" disabled={loading || !authorized}>{loading ? "Scanning…" : "Scan website →"}</button></div>
          <p className="field-help" id="url-help">Public HTTP and HTTPS sites. Anonymous, read-only checks with a 50-second scan budget.</p>
          <details className="scan-options"><summary>Scan options</summary><div className="options-grid"><label htmlFor="page-limit">Page limit<select id="page-limit" value={maxUrls} disabled={loading} onChange={(event) => setMaxUrls(Number(event.target.value))}>{[1, 5, 10, 20].map((count) => <option value={count} key={count}>{count} {count === 1 ? "page" : "pages"}</option>)}</select></label><label htmlFor="depth-limit">Link depth<select id="depth-limit" value={maxDepth} disabled={loading} onChange={(event) => setMaxDepth(Number(event.target.value))}>{[0, 1, 2, 3].map((depth) => <option value={depth} key={depth}>{depth === 0 ? "Starting page only" : `${depth} ${depth === 1 ? "level" : "levels"}`}</option>)}</select></label></div></details>
          <label className="permission"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} required disabled={loading} /><span>I own this website or have permission to scan it.</span></label>
          {loading ? <div className="loading-state" role="status"><span className="spinner" aria-hidden="true" /><p>Reviewing public pages and security settings…</p><button type="button" className="text-button" onClick={() => controller.current?.abort()}>Stop waiting</button></div> : null}
        </form>
        <details className="panel source-review"><summary>Review source code or open a saved report <span>Local files stay in your browser</span></summary><div className="coverage-content"><p>For authentication logic, PDF rendering, email endpoints and container configuration, run the local source review in your own checkout:</p><pre><code>python backend/source_audit.py /path/to/project --output report.json</code></pre><p>Add <code>--npm-audit</code> to query current dependency advisories. Source findings are heuristic review prompts; this tool does not prove exploitability or execute your application.</p><p>Open the generated report below to explore issues and repair steps. Only the JSON report is read locally; no source code is uploaded.</p><input ref={importInput} type="file" accept=".json,application/json" className="sr-only" tabIndex={-1} aria-label="Select a saved scan report" onChange={importReport} disabled={loading} /><button type="button" className="secondary" disabled={loading} onClick={() => importInput.current?.click()}>Open JSON report</button></div></details>
        {error ? <div className="notice notice-error" role="alert">{error}</div> : null}
        {results ? <section className="results" aria-labelledby="results-heading">
          <div className="results-header"><div><p className="eyebrow">{results.mode === "source" ? "Local source review · heuristic findings" : "Passive scan results"}</p><h2 id="results-heading" tabIndex={-1} ref={resultHeading}>{results.vulnerabilities.length} {results.vulnerabilities.length === 1 ? "finding" : "findings"} to review</h2><p>{results.scanned_urls.length} {results.mode === "source" ? "files reviewed" : "pages analyzed"} · {results.requests_made} crawl requests · {results.duration_seconds}s</p></div><button type="button" className="secondary" onClick={exportReport}>Download JSON ↓</button></div>
          <p className="report-target">{results.target}</p>
          {!results.complete ? <div className="notice notice-warning">{results.mode === "source" ? "Source review uses pattern matching. Check middleware, helper functions, infrastructure and runtime behavior before treating any result as a confirmed vulnerability." : "Coverage is incomplete. Some pages were skipped or a scan limit was reached. Expand scan coverage for details."}</div> : null}
          <div className="severity-stats" aria-label="Findings by severity">{severities.map((item) => <button type="button" key={item} className={`stat stat-${item}${severity === item ? " selected" : ""}`} aria-pressed={severity === item} onClick={() => setSeverity(severity === item ? "all" : item)}><strong>{results.summary[item]}</strong><span>{item === "info" ? "Informational" : `${item} severity`}</span></button>)}</div>
          {results.vulnerabilities.length > 0 ? <><div className="filters"><label htmlFor="finding-search"><span className="sr-only">Search issues</span><input id="finding-search" type="search" placeholder="Search issue or page…" value={search} onChange={(event) => setSearch(event.target.value)} /></label><label htmlFor="severity-filter"><span className="sr-only">Filter severity</span><select id="severity-filter" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option>{severities.map((item) => <option key={item} value={item}>{item === "info" ? "Informational" : item}</option>)}</select></label></div><div className="findings-heading"><h3>Issues found</h3><span aria-live="polite">{visible.length} of {results.vulnerabilities.length}</span></div><p className="field-help">Select an issue’s ⓘ details to see why it matters and how to fix it.</p><div className="finding-list">{visible.map((finding) => <FindingCard key={finding.id} finding={finding} />)}</div>{visible.length === 0 ? <p className="empty-state">No issues match these filters.</p> : null}</> : <p className="empty-state">{results.scanned_urls.length ? "No findings from the passive checks on the pages analyzed." : "No pages were analyzed. Review the coverage warnings below."}</p>}
          <details className="panel coverage"><summary>Scan coverage <span>{results.scanned_urls.length} {results.mode === "source" ? "files" : "pages"} · {results.warnings.length} warnings</span></summary><div className="coverage-content">{results.url_limit_exceeded ? <p className="coverage-warning">The page limit was reached. Additional linked pages were skipped.</p> : null}{results.time_limit_exceeded ? <p className="coverage-warning">The scan time limit was reached.</p> : null}{results.request_limit_exceeded ? <p className="coverage-warning">The request limit was reached.</p> : null}{results.warnings.map((warning, index) => <div className="coverage-warning" key={`${warning.code}-${index}`}><p>{warning.message}</p><code>{warning.url}</code></div>)}<h3>{results.mode === "source" ? "Files reviewed" : "Analyzed pages"}</h3><ul>{results.scanned_urls.map((page, index) => <li key={`${page}-${index}`}><code>{page}</code></li>)}</ul></div></details>
          <p className="limitations">Passive scans review public responses; source reviews identify code patterns. Neither can guarantee security or confirm every exploit. Severity is a qualitative priority, not a CVSS score. Findings require context and manual review. Query values and matched secrets are omitted from generated reports; paths and variable names may still be sensitive.</p>
        </section> : <section className="how-it-works" aria-label="How it works"><div><span>01</span><h2>Review public pages</h2><p>A bounded crawl checks the site’s publicly visible responses.</p></div><div><span>02</span><h2>Prioritize findings</h2><p>See each issue with its severity and detection confidence.</p></div><div><span>03</span><h2>Make a focused fix</h2><p>Expand any issue for clear repair steps and verification.</p></div></section>}
        <footer>WebsiteThreatScan · Practical security starts with informed decisions.</footer>
      </div>
    </main>
  );
}
