"""Opt-in, local heuristic source review. Does not execute target application code.

Usage: python backend/source_audit.py /path/to/project --output report.json
Add --npm-audit to query package advisories using existing package-lock.json files.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
SKIP = {"node_modules", ".git", ".next", ".venv", "venv", "dist", "build", "coverage", "vendor", "__pycache__", "tests", "__tests__", "fixtures", ".aws", ".codex", ".agents"}
EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}
AUTH = r"(?:getUser|getSession|auth|requireAuth|verifySession|currentUser|withAuth|authenticate|verifyToken)\s*\("
RATE = r"rateLimit|ratelimit|throttle|limiter"


def source_audit(root, npm_audit=False):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("The source path must be an existing directory.")
    started = time.monotonic()
    findings, warnings, scanned, locks = [], [], [], []
    env_uses, documented = set(), set()
    total_bytes = 0

    def finish():
        return _report(findings, warnings, scanned, started)

    def warn(code, path, message):
        if len(warnings) < 100:
            warnings.append(dict(code=code, url=path, message=message))

    def add(code, title, severity, path, text, pattern, reason, steps, verification, confidence="low", details=None):
        if len(findings) >= 500:
            warn("finding_limit", path, "The 500-finding source review limit was reached.")
            return
        match = re.search(pattern, text, re.I | re.S) if pattern else None
        line = text.count("\n", 0, match.start()) + 1 if match else 1
        location = f"{path}:{line}"
        identifier = hashlib.sha256(f"{code}|{location}".encode()).hexdigest()[:16]
        findings.append(dict(id=identifier, code=code, type=title, severity=severity, level=severity,
                             url=location, confidence=confidence,
                             details=details or "A source pattern suggests this weakness. Middleware, imported helpers, infrastructure or unused code may change the outcome. No exploit was attempted; verify manually.",
                             severity_reason=reason, fix_steps=steps, verification=verification,
                             remediation=steps[0], reference=REFERENCE))

    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith(".") and not (Path(directory) / d).is_symlink())
        for filename in sorted(files):
            path = Path(directory) / filename
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                continue
            if filename == "package-lock.json":
                if len(locks) < 10:
                    locks.append(path)
                else:
                    warn("lockfile_limit", relative, "Only the first 10 npm lockfiles are reviewed.")
                continue
            if filename.startswith(".env") and filename not in {".env.example", ".env.local.example"}:
                continue
            if path.suffix not in EXTENSIONS and filename not in {"Dockerfile", ".env.example", ".env.local.example"}:
                continue
            if re.search(r"\.(?:test|spec)\.[cm]?[jt]sx?$", filename):
                continue
            if len(scanned) >= 2000 or total_bytes >= 10_485_760:
                warn("source_limit", relative, "Source review reached 2000 files or 10 MiB; remaining files were skipped.")
                return finish()
            try:
                with path.open("rb") as handle:
                    raw = handle.read(524_289)
                if len(raw) > 524_288:
                    warn("file_limit", relative, "Source file larger than 512 KiB was skipped.")
                    continue
                text = raw.decode("utf-8")
            except (OSError, UnicodeError):
                warn("source_unreadable", relative, "Source file could not be read as UTF-8.")
                continue
            total_bytes += len(raw)
            scanned.append(relative)
            if filename in {".env.example", ".env.local.example"}:
                documented.update(re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s*=", text, re.M))
                continue
            env_uses.update(re.findall(r"process\.env\.([A-Z][A-Z0-9_]*)", text))
            if filename == "Dockerfile":
                # The last FROM starts the runtime stage. A USER in a build stage is insufficient.
                stage = re.split(r"^\s*FROM\s+", text, flags=re.I | re.M)[-1]
                users = re.findall(r"^\s*USER\s+([^\s#]+)", stage, re.I | re.M)
                if not users or users[-1].lower().split(":")[0] in {"root", "0"}:
                    add("source.container_user", "Review container runtime user", "low", relative, text, None,
                        "Low: the final Docker stage has no explicit non-root user, or selects root. Base-image defaults may already be non-root and require inspection.",
                        ["Inspect the final base image's configured user.", "Create or select an unprivileged runtime user after installing dependencies.", "Set USER node or an appropriate non-root UID in the final stage and grant only needed file permissions."],
                        "Inspect the built image's Config.User and run id in the container; confirm the app works without root.")
                continue
            browser = re.search(r"(?:chromium|puppeteer|firefox|webkit)\.launch\s*\(", text)
            if "--no-sandbox" in text:
                add("source.browser_sandbox", "Browser sandbox disabled", "high", relative, text, "--no-sandbox",
                    "High: a compromised renderer may cross fewer process isolation boundaries when Chromium's sandbox is disabled. Exposure depends on whether untrusted content reaches the browser.",
                    ["Remove --no-sandbox and configure a supported browser sandbox in the deployment.", "Run the renderer as an unprivileged user in a dedicated isolated service.", "Keep Chromium patched and restrict filesystem mounts, credentials and network egress."],
                    "Verify the production launch flags and sandbox support; render a harmless document under the restricted runtime.", "medium")
            if re.search(r"\.setContent\s*\(|\.goto\s*\(", text) and re.search(r"request\.(?:json|text)|req\.body|body\.html|\bhtml\b", text):
                add("source.browser_input", "Review untrusted browser rendering and SSRF defenses", "high", relative, text, r"\.setContent\s*\(|\.goto\s*\(",
                    "High: request-driven rendering may fetch internal services or expose local resources if untrusted URLs or HTML reach a privileged browser. This pattern alone does not prove access.",
                    ["Require authentication and authorize rendering jobs.", "Prefer trusted templates with escaped variables; constrain raw HTML, scripts and resource types.", "Allowlist outbound resources at browser-context level, block service workers, and validate redirects and all resolved IPs.", "Deny file and non-HTTP schemes, private/link-local/loopback IPv4 and IPv6, metadata networks and DNS rebinding at a separate network egress boundary.", "Run the browser without app secrets or sensitive mounts; do not rely on page.route alone."],
                    "In an isolated staging environment, verify that controlled blocked resources cannot be fetched and that allowed assets still render.")
            if browser and not re.search(r"p-limit|PQueue|Semaphore|browserPool|queue\.add|withConcurrency|acquire\s*\(", text):
                add("source.browser_capacity", "Review browser process concurrency", "medium", relative, text, r"\.launch\s*\(",
                    "Medium: launching browsers without a visible concurrency boundary can exhaust CPU or memory. An external worker pool may already provide the boundary.",
                    ["Use a bounded worker queue or reusable browser pool with isolated contexts.", "Cap concurrent render jobs and queue length; reject excess work with a retry response.", "Apply per-user rate limits and per-job deadlines; close contexts and browsers in finally blocks."],
                    "Load-test only staging within agreed limits and confirm stable memory, bounded jobs and cleanup after failures.")
            if re.search(r"document\.cookie\s*=", text) and re.search(r"supabase|access_token|refresh_token|auth.token|session", text, re.I):
                add("source.auth_cookie", "Review JavaScript-readable authentication storage", "medium", relative, text, r"document\.cookie\s*=",
                    "Medium: scripts can read JavaScript-managed authentication cookies, increasing token exposure if XSS occurs. Supabase browser sessions may intentionally require this access.",
                    ["Review whether browser code needs direct access to Supabase session tokens.", "For a server-only session design, use a backend-for-frontend with server-managed HttpOnly, Secure and appropriate SameSite cookies.", "If retaining browser-managed sessions, use the supported Supabase SSR flow, strict XSS defenses and short-lived tokens; installing @supabase/ssr alone does not make cookies HttpOnly.", "Never expose service-role keys in client bundles."],
                    "Verify the intended session architecture, cookie flags and token refresh/login flows without breaking required client-side access.", "medium")
            route = bool(re.search(r"(?:^|/)(?:api|routes?)/", relative) or filename.startswith("route."))
            if not route:
                continue
            has_auth = bool(re.search(AUTH, text))
            if re.search(r"(?:request|req)\.(?:json|body)", text) and re.search(r"role\s*:\s*(?:role\b|(?:body|data|payload)\.role\b)", text) and re.search(r"signup|sign.up|register", relative, re.I):
                add("source.signup_role", "Potential client-controlled signup role", "critical", relative, text, r"role\s*:\s*(?:role\b|(?:body|data|payload)\.role\b)",
                    "Critical if confirmed: accepting an administrative role during public signup can grant full control over accounts and customer data. Role allowlists and database policies must be checked.",
                    ["Ignore privileged role fields in public signup requests and assign the least-privileged role on the server.", "Require independent administrator authorization for later role changes.", "Enforce database row-level security and prevent users from editing their own privilege fields.", "Review existing accounts for unexpected privileges."],
                    "Using a disposable staging account, submit an unexpected role and confirm the stored role and actual permissions remain unprivileged.")
            verifies = re.search(r"email_verified\s*:\s*true|email_confirm\s*:\s*true|email_confirmed_at\s*:", text)
            if verifies and re.search(r"verify.email|confirm.email", relative, re.I) and not re.search(r"verifyOtp\s*\(|timingSafeEqual\s*\(|jwtVerify\s*\(|verifyToken\s*\(", text):
                add("source.email_verification", "Review email verification proof validation", "critical", relative, text, r"email_verified\s*:\s*true|email_confirm\s*:\s*true|email_confirmed_at\s*:",
                    "Critical if confirmed: marking an address verified without valid proof bypasses inbox ownership checks and may undermine account trust. Imported verification helpers may provide protection.",
                    ["Use the provider's validated email OTP or token-hash flow, such as Supabase auth.verifyOtp.", "For custom tokens, validate signature, intended account and purpose, expiry and single-use consumption on the server.", "Never use a bare email address as proof; reject missing, invalid, expired or replayed tokens."],
                    "With disposable staging accounts, verify that invalid, expired, replayed and missing proofs never mark an email as verified.")
            if re.search(r"password.reset|reset.password", relative, re.I) and re.search(r"no account|user not found|email (?:not|does not)|not registered", text, re.I):
                add("source.account_enumeration", "Potential password-reset account enumeration", "medium", relative, text, r"no account|user not found|email (?:not|does not)|not registered",
                    "Medium: different account-existence responses can expose which emails are registered. Reachability, response codes and timing must be verified.",
                    ["Return the same generic message and HTTP status for registered and unregistered addresses.", "Queue delivery and avoid materially different response timing.", "Apply per-account and per-client rate limits without revealing account existence."],
                    "Compare status, response body and timing distributions for two controlled staging addresses; avoid testing real users.")
            sends_mail = bool(re.search(r"sendMail\s*\(|sendEmail\s*\(|\.emails\.send\s*\(", text))
            if sends_mail and not has_auth:
                add("source.email_authorization", "Review email endpoint authorization", "high", relative, text, r"sendMail\s*\(|sendEmail\s*\(|\.emails\.send\s*\(",
                    "High if confirmed: unrestricted email jobs or attacker-controlled recipients may enable spam and phishing. Public transactional flows may use purpose-bound proof instead of a session.",
                    ["Authorize each mail operation, or require purpose-bound proof for public signup/reset flows.", "Resolve recipients from trusted server-side records rather than arbitrary request input.", "Constrain templates, links and message type; add per-user, recipient and IP quotas."],
                    "Use a staging mail sink to confirm unauthorized jobs and arbitrary recipients are rejected without sending real email.")
            if sends_mail and re.search(r"\$\{", text) and not re.search(r"escapeHtml|escapeHTML|htmlEscape|sanitizeHtml|DOMPurify", text):
                add("source.email_html", "Review email template escaping", "medium", relative, text, r"\$\{",
                    "Medium: template interpolation may inject attacker-controlled HTML or links into trusted email. The interpolated values may already be trusted or escaped elsewhere.",
                    ["Escape text variables for their HTML context or use a template engine that escapes by default.", "Validate link schemes and destinations separately; HTML escaping does not make an arbitrary link safe.", "Keep recipient, subject and sender headers validated and server controlled."],
                    "Render harmless special characters in a staging mail sink and confirm they appear as text, with untrusted links rejected.")
            if (sends_mail or browser) and not re.search(RATE, text):
                add("source.endpoint_rate", "Review expensive endpoint rate limits", "medium", relative, text, None,
                    "Medium: email or rendering work can be abused without admission limits. Shared middleware, gateways or queues may already enforce limits.",
                    ["Check gateway and middleware limits before adding duplicate controls.", "Apply shared per-principal and per-IP limits, bounded queues and request deadlines.", "Return 429 or 503 with Retry-After when limits are reached."],
                    "In staging, confirm bounded request bursts are rejected and do not create unbounded jobs.")

    missing = sorted(env_uses - documented - {"NODE_ENV", "PORT", "CI", "VERCEL", "VERCEL_ENV", "VERCEL_URL"})
    if missing:
        add("source.env_docs", "Environment configuration documentation gaps", "low", ".env.example", "", None,
            "Low: undocumented environment settings make setup and deployment errors more likely. Optional settings and workspace-level examples may make some omissions intentional.",
            ["Review which referenced variables are required in each environment.", "Add safe placeholder entries and descriptions to the relevant environment example file.", "Mark server-only secrets clearly and never prefix them with NEXT_PUBLIC_.", "Do not copy real credentials into examples or version control."],
            "Set up a clean development environment from the documentation and confirm all required settings are covered.",
            "medium", "Referenced names absent from collected example files: " + ", ".join(missing[:100]))

    if npm_audit:
        for lock in locks:
            relative = lock.relative_to(root).as_posix()
            if not shutil.which("npm"):
                warn("audit_unavailable", relative, "npm is not available; dependency advisory review was skipped.")
                continue
            try:
                result = subprocess.run(["npm", "audit", "--json", "--ignore-scripts", "--package-lock-only"], cwd=lock.parent,
                                        capture_output=True, text=True, timeout=60, check=False)
                advisory = json.loads(result.stdout)
                if "error" in advisory or result.returncode not in {0, 1} or not isinstance(advisory.get("vulnerabilities"), dict):
                    raise ValueError()
                for name, issue in sorted(advisory["vulnerabilities"].items()):
                    severity = issue.get("severity", "info")
                    if severity not in {"critical", "high", "medium", "moderate", "low", "info"}:
                        severity = "info"
                    severity = "medium" if severity == "moderate" else severity
                    add(f"dependency.{name}", f"Dependency advisory: {name}", severity, relative, "", None,
                        f"{severity.capitalize()}: npm audit reports an affected dependency range. Installed version, production usage and exploit prerequisites determine actual impact; this is not a CVSS calculation.",
                        ["Review npm audit's advisory and affected dependency paths locally.", "Upgrade to a patched compatible release; inspect breaking changes before forcing upgrades.", "Refresh the lockfile, run application tests and repeat npm audit."],
                        "Confirm the affected dependency path is patched and that the relevant application flow still works.",
                        "medium", f"npm audit flagged package {name}. Affected range: {str(issue.get('range', 'unknown'))[:200]}. No target application code was executed.")
            except (OSError, subprocess.TimeoutExpired, ValueError, KeyError):
                warn("audit_failed", relative, "Dependency audit did not return a usable advisory report. No clean dependency claim is made.")
    elif locks:
        warn("audit_not_run", "package-lock.json", "Dependency advisories were not queried. Use --npm-audit to opt in to registry access.")

    return finish()

def _report(findings, warnings, scanned, started):
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (ranks[f["severity"]], f["url"], f["code"]))
    return dict(schema_version=2, mode="source", target="Local source review", generated_at=datetime.now(timezone.utc).isoformat(),
                vulnerabilities=findings, scanned_urls=scanned, attempted_urls=len(scanned), requests_made=0,
                duration_seconds=round(time.monotonic() - started, 2), summary={s: sum(f["severity"] == s for f in findings) for s in ranks},
                complete=False, warnings=warnings, url_limit_exceeded=False, time_limit_exceeded=False, request_limit_exceeded=False,
                message="Heuristic local source review. Results are candidates for manual verification, not confirmed vulnerabilities.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path, help="Write the JSON report to a file instead of stdout.")
    parser.add_argument("--npm-audit", action="store_true", help="Query package advisories via npm audit; makes registry requests but does not run application scripts.")
    args = parser.parse_args()
    try:
        report = source_audit(args.path, npm_audit=args.npm_audit)
    except ValueError as exc:
        parser.error(str(exc))
    payload = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(payload)
    else:
        print(payload, end="")
