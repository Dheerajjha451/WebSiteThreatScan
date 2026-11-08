# API contract

## Health

`GET /health` on the Flask backend returns `{"status":"ok","version":"2.0","mode":"passive"}`. It checks that the process is responsive, not target DNS or network availability. It does not require the optional scan API key.

## Public scans

The browser calls `POST /api/scan` on Next.js. Trusted API clients can call `POST /scan` on Flask. Both expect `Content-Type: application/json` and cap request bodies at 8 KiB. When `SCANNER_API_KEY` is configured, direct backend clients must send `Authorization: Bearer <key>`. The frontend proxy supplies the key from server configuration.

```json
{
  "url": "https://example.com/",
  "authorized": true,
  "max_urls": 10,
  "max_depth": 2
}
```

`authorized` must be the boolean `true`; this is an attestation, not proof of ownership or user authentication. Unknown options are rejected. `max_urls` defaults to 10, with allowed integer values 1–20; `max_depth` defaults to 2, with allowed integers 0–3. Booleans are not accepted as integers. The target must be a public HTTP(S) URL without credentials, whitespace or backslashes and at most 2048 characters. Only the scheme's standard port is accepted.

### Response schema 2

A successful report includes:

| Field | Meaning |
| --- | --- |
| `schema_version`, `mode` | `2` and `passive` (`source` for local CLI reports) |
| `target`, `generated_at` | Redacted target and UTC timestamp |
| `vulnerabilities` | Findings with `id`, `code`, `type`, `severity`, legacy `level`, `url`, `details`, `confidence`, `severity_reason`, `fix_steps`, `verification`, `remediation`, `reference` |
| `summary` | Counts for `critical`, `high`, `medium`, `low`, `info` |
| `scanned_urls` | Successfully analyzed page URLs, with query values redacted; source reports use relative file paths |
| `attempted_urls`, `requests_made` | Crawl entry count and actual outbound GET count, including redirects |
| `duration_seconds` | Elapsed time, rounded to two decimals |
| `complete` | False for failed/skipped pages, depth truncation, crawl/response limits, or any warning; source reviews are always incomplete heuristic reviews |
| `warnings` | Objects containing `code`, redacted `url` and `message` |
| `url_limit_exceeded`, `time_limit_exceeded`, `request_limit_exceeded` | Coverage flags |
| `limits` | Runtime limits (public scan only) |
| `message` | Human-readable review caveat |

Severity is qualitative priority, **not a numeric CVSS score**. Confidence is the certainty of the observation or heuristic, not the chance of exploitation. IDs are stable hashes of rule, redacted location and relevant subject, allowing duplicate suppression. Query variants with identical redacted locations may share an issue ID; do not use IDs as a global vulnerability database key.

### Status codes

| Status | Meaning |
| --- | --- |
| 200 | At least one page analyzed; inspect `complete` and warnings for partial results |
| 400 | Malformed JSON, target, permission attestation or options |
| 401 | Missing/invalid configured backend bearer token (proxy masks configuration failures as 502) |
| 403 | Browser Origin differs from the Next.js endpoint's origin |
| 413 | Request exceeds 8 KiB |
| 415 | Unsupported request Content-Type |
| 422 | No page was analyzed; the report and warnings are retained, not presented as a clean scan |
| 429 | Process-local client quota reached; `Retry-After: 60` |
| 500 | Sanitized unexpected backend failure |
| 502 / 504 | Proxy upstream error / timeout |
| 503 | Scanner capacity reached (`Retry-After: 10`) or bad proxy configuration |

### Fixed outbound limits

- 50 seconds for the complete async crawl; 10 seconds per request, with a 5-second connect timeout.
- 60 total GET requests, including redirects; at most 5 redirect hops per crawl entry.
- 1 MiB of decompressed response content per page; excess content is truncated with a warning.
- At most 50 forms reviewed per page, and 500 findings per report; omitted content is flagged.
- Two concurrent scans and five accepted attempts per client IP per rolling minute per backend process. Busy attempts count toward the quota. Forwarding headers are not trusted.
- The proxy waits at most 55 seconds for an upstream response and accepts at most 2 MiB of report data. The browser stops waiting after 65 seconds.

Links are deduplicated, fragments removed, and query strings preserved for fetching. Only the same hostname is followed. HTTP-to-HTTPS upgrades are permitted; cross-host redirects and HTTPS-to-HTTP redirects are blocked. `www` is a different hostname: start with the site's final canonical URL. Subresource URLs are inspected in markup but not fetched. Forms are never submitted, and injected payloads are never sent.

Stopping the browser's wait does not cancel a scan already admitted by Flask. The server continues until its own deadline or budgets are reached.
