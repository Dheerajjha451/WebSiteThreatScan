# Changes — 2026-11-08

## Finding explanations and workflow

- Findings are collapsed by default. Selecting their ⓘ details reveals the observation, why the severity was assigned, confidence, numbered repair choices and verification steps.
- Added severity counts and filters (including Critical for source reviews), search, deterministic finding IDs, JSON download, keyboard-accessible disclosures, loading/error states and scan coverage details.
- Added browser-local import of schema 2 reports. Imports are size/schema checked and are not uploaded or persisted. Reference links are restricted to OWASP's HTTPS cheat-sheet site.
- Added page/depth controls and permission attestation. A stopped wait and a failed/partial scan are clearly distinguished from a successful result.

## Public-response checks

Added/reworked checks for enforced and permissive CSP, HSTS, clickjacking protection, MIME sniffing, referrer and permissions policies, cookie flags and prefixes, wildcard CORS review, implementation header disclosures, mixed HTTP content, password form handling, POST-form CSRF review, directory listings, database error disclosures, credential/webhook patterns and Supabase-style privileged keys. Public anon/publishable keys are not treated as service-role secrets.

Cookie parsing now handles independent Set-Cookie headers, Expires commas and case-insensitive attributes. A page with no Set-Cookie header no longer produces a phantom cookie finding. Plain mentions of SQL products no longer imply injection; missing CSRF fields and intentional public CORS are explicitly contextual review prompts. A non-200 response is no longer called a certificate problem.

## Source review

Added `backend/source_audit.py` for local review of the user-supplied issue classes: request-controlled signup roles, email-verification proof, reset enumeration, unsafe browser launch/content handling, process concurrency, JS authentication cookies, mail authorization/template escaping/rate limits, final-stage Docker users and missing environment documentation. `--npm-audit` optionally adds current dependency advisories without running application scripts or applying fixes. Reports use relative paths/line locations and omit code snippets and secret values.

This is bounded pattern matching, not a parser, taint engine or a proof of vulnerability. Source findings are verification candidates, even when their potential severity is critical. Middleware, imported controls, comments, infrastructure and deployment behavior can change conclusions.

## Scanner and service security

- Replaced the blocking, unverified crawler and repeated per-check fetches with one bounded asynchronous fetch per page, followed by local analysis.
- Enabled normal TLS verification; removed global certificate warning suppression.
- Added strict URL validation, public IP checks at connection-time DNS resolution, checks of every DNS answer, manual redirect policy and exact-host crawl scoping. Unsupported IPv6 transition/translation ranges are rejected. No environment proxies or persisted target cookies are used.
- Enforced crawl, request, time, queue, response and result budgets. Failures produce coverage warnings and partial reports.
- Added bounded process-local admission/rate controls, optional backend bearer authentication, explicit opt-in CORS, health endpoint, no-store responses, security headers, generic internal errors and loopback-only development binding with debug disabled.
- Replaced the public backend URL variable with a same-origin Next.js proxy and server-only backend credentials.
- Upgraded runtime packages and framework/tooling, removed unused Python media/PDF/network dependencies and frontend axios/cheerio/toast/CSS-build dependencies, and added repeatable quality/audit commands, CI and Dependabot configuration.

## Migration notes

- **Active SQL/XSS/traversal/command execution probes were removed.** Earlier checks sent invasive payloads and made unreliable claims; v2 makes anonymous GET observations. Tests requiring state changes or exploit payloads belong in an independently authorized staging review.
- Direct API clients must now send `authorized: true`. Unknown options, private targets, custom ports, malformed URLs and credential-bearing URLs are rejected.
- Use `SCANNER_API_URL` and optional `SCANNER_API_KEY` on the Next.js server. Remove `NEXT_PUBLIC_BASE_URL`. The key must match the backend configuration.
- The framework is now Next.js 16 with React 19. Use Node.js 22.13+ (CI uses 24); the test command imports TypeScript directly through Node's supported type stripping. Lint uses ESLint directly instead of removed `next lint`.
- Python runtime dependencies are pinned for Python 3.12+. Development/audit tools are in `backend/requirements-dev.txt`.
- System fonts remove the build's Google Fonts download dependency. Styling is local CSS.
- Legacy `vulnerabilities`, `scanned_urls` and `level` remain, but consumers should use schema 2 and the typed `severity`, explanation and coverage fields. A result with no analyzed pages now returns HTTP 422.

## Validation

See the repository's tests and CI workflow for repeatable checks. The backend tests cover URL/DNS and redirect policies, budgets, analysis/redaction, API errors/admission, all source-review example categories and real HTTP transport through a controlled local fixture. Frontend tests cover schema validation, filters, export names and reference-link restrictions. No test sends exploit payloads or scans a third-party site.
