# Security model and operation

## Outbound requests

The service accepts only HTTP/HTTPS targets on standard ports, without URL credentials. URL validation rejects internal literal IPs, unusual schemes, invalid hosts and ambiguous separators. Every DNS answer supplied to the actual connection is validated as a global unicast address; mixed public/private answers are rejected. IPv4-mapped, 6to4, Teredo and known NAT64 translation addresses are unsupported. This closes the separate-lookup DNS rebinding gap. aiohttp's normal TLS certificate/hostname checks stay enabled.

Redirects are manual and bounded, keep the same hostname, and cannot downgrade HTTPS. Linked pages use the same policy. The scanner uses anonymous GET requests, no target authentication, no cookie persistence and no environment proxies. It never submits forms, executes target scripts or sends injection payloads. GET endpoints with incorrect state-changing behavior can still have side effects: only review authorized targets.

Application validation is defense in depth, not a replacement for network isolation. Block private, loopback, link-local and cloud metadata networks at the deployment's egress boundary, including IPv6 and provider-specific paths. Use a private backend network and minimum permissions. Public Internet addresses can still point to sensitive services; use your own domain allowlist at the edge when operating in a restricted organization.

## Service admission and access

Local development binds Flask to loopback with debug disabled. Use Gunicorn or another production WSGI server. Optional SCANNER_API_KEY authenticates calls to the backend; the Next.js server holds the matching key. It does not log in frontend users or prove domain ownership. Add product-level authentication/authorization and shared per-user/domain/IP quotas before a multi-tenant deployment.

The process guard permits two scans in flight and five admitted attempts per remote IP per minute, with a bounded 4096-client map. Counts reset on restart; eviction can reset old-client quotas. Multiple workers/instances multiply capacity and quotas. Through the Next.js proxy, Flask normally sees the proxy's IP, so the local quota is shared across its users. Configure shared admission/rate limits at the gateway for scale. Do not blindly trust X-Forwarded-For; if proxy trust is needed, restrict it to known infrastructure and an exact hop count.

CORS is disabled unless SCANNER_ALLOWED_ORIGINS explicitly lists allowed origins; wildcard configuration is rejected. The browser normally uses the same-origin Next.js proxy. Its Origin check compares the browser Origin with the incoming Host and request protocol; set SCANNER_APP_ORIGIN to your exact public HTTPS origin behind a reverse proxy. This prevents ordinary cross-origin browser submissions; it is not an authentication mechanism and cannot stop non-browser clients. Body limits, timeouts, redirect limits, result caps and response-size limits bound resource use.

## Browser security

The Next.js app and Flask API set nosniff, frame, referrer and permissions protections. API responses use no-store. The frontend CSP restricts sources, object embeds, forms and framing; it currently permits inline scripts/styles for Next.js rendering, and development also permits eval. This is a documented defense-in-depth baseline, not a strict nonce CSP. A production nonce policy requires deliberate dynamic-rendering integration. Set HSTS at your HTTPS deployment edge after validating domain scope; it is intentionally not forced on local HTTP servers.

Target HTML is parsed only by the backend and is never rendered as HTML in the UI. React renders finding strings as text. Imported report references must be HTTPS links to OWASP's cheat-sheet hostname. Report imports are limited to 2 MiB and checked before rendering. Their contents are untrusted and are not proof that a scan was actually run.

## Privacy

Raw cookie values, matched credential strings, response bodies and query values are omitted from generated findings. Query values are replaced with [redacted] in reported URLs, while full queries remain in memory long enough to perform the requested GET. Findings and warnings include paths, filenames, variable names and cookie names: those can themselves contain sensitive information. Do not put secrets in URL paths or filenames; review reports before sharing them.

The application does not intentionally persist reports, save scanned content or log complete targets/findings. Downloaded JSON is explicitly saved by the user. Import reads reports in the browser without uploading or browser persistence. Reverse proxies, hosting access logs, browser history and infrastructure may record requests independently; configure those systems for your retention/privacy requirements. Python source review runs locally and does not upload source; --npm-audit sends package audit metadata to the registry configured for npm. Avoid enabling it where that metadata must remain offline.

Source review does not execute application code or run install/build scripts. It skips real environment files and symlinks, bounds file reads and omits source snippets. Run it on your own stable checkout; it is not designed as an isolated hostile-repository processing service.

## Maintenance and disclosure

CI performs backend tests, frontend quality checks/builds and current dependency audits. Advisory databases change; a clean audit is a point-in-time result, not a lasting guarantee. Review compatible upgrades and breaking changes before deployment; do not blindly force dependency fixes. Dependabot proposes updates for review.

Report a suspected security vulnerability privately through the repository owner's preferred private security channel. Avoid posting live credentials, exploitation details against third-party sites, personal data or unredacted reports in public issues.
