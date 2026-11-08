"""Passive checks. Findings are observations, not proof of exploitability."""
import hashlib
import base64
import json
import re
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from guidance import explain
from targets import redact_url

HEADER_GUIDE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
COOKIE_GUIDE = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"


def resource_scheme(base, resource):
    try:
        return urlsplit(urljoin(base, resource)).scheme
    except ValueError:
        return ""


def analyze_page(url, text, headers, is_html):
    findings = []

    def add(code, title, severity, details, remediation, reference=HEADER_GUIDE, confidence="high", subject=""):
        safe_url = redact_url(url)
        identifier = hashlib.sha256(f"{code}|{safe_url}|{subject}".encode()).hexdigest()[:16]
        if len(findings) >= 100:
            return
        findings.append(explain(dict(id=identifier, code=code, type=title, severity=severity,
                             level=severity, url=safe_url, details=details,
                             remediation=remediation, reference=reference, confidence=confidence)))

    https = urlsplit(url).scheme == "https"
    if not https:
        add("transport.http", "Unencrypted HTTP response", "high", "This response was served over HTTP.",
            "Serve the site over HTTPS and redirect HTTP requests to HTTPS.")
    if https and not re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9]\d*\s*(?:;|$)", headers.get("Strict-Transport-Security", ""), re.I):
        add("headers.hsts", "Missing or ineffective HSTS", "medium", "No positive HSTS max-age was observed.",
            "Enable Strict-Transport-Security after confirming HTTPS works across the intended domain scope.")
    if headers.get("X-Content-Type-Options", "").lower().strip() != "nosniff":
        add("headers.nosniff", "Missing MIME sniffing protection", "low", "X-Content-Type-Options is not nosniff.",
            "Send X-Content-Type-Options: nosniff with accurate Content-Type headers.")
    if is_html:
        csp = headers.get("Content-Security-Policy", "")
        directives = {}
        for part in csp.lower().split(";"):
            tokens = part.split()
            if tokens:
                directives.setdefault(tokens[0], tokens[1:])
        if not csp:
            add("headers.csp", "Missing enforced Content Security Policy", "medium",
                "No enforced CSP response header was observed; report-only policies do not enforce restrictions.",
                "Deploy a tested CSP using nonces or hashes and narrowly scoped sources.")
        else:
            script_sources = directives.get("script-src", directives.get("default-src", []))
            if not script_sources or any(value in script_sources for value in ("*", "'unsafe-inline'", "'unsafe-eval'", "data:")):
                add("headers.csp_weak", "Review permissive script policy", "medium",
                    "The CSP permits broad script sources or has no script restriction. Nonces and browser behavior need manual review.",
                    "Restrict script-src; replace unsafe directives with nonces or hashes where supported.", confidence="medium")
        if headers.get("X-Frame-Options", "").upper().strip() not in {"DENY", "SAMEORIGIN"} and not directives.get("frame-ancestors"):
            add("headers.framing", "Missing frame embedding protection", "medium", "Neither a valid X-Frame-Options nor CSP frame-ancestors was observed.",
                "Set CSP frame-ancestors to the required origins, or use X-Frame-Options: DENY or SAMEORIGIN.")
        policies = [item.strip().lower() for item in headers.get("Referrer-Policy", "").split(",")]
        supported = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
        effective = next((item for item in reversed(policies) if item in supported), "")
        if effective in {"", "unsafe-url", "no-referrer-when-downgrade"}:
            add("headers.referrer", "Review referrer policy", "low", "No explicit privacy-preserving Referrer-Policy was observed.",
                "Set Referrer-Policy: strict-origin-when-cross-origin, or a stricter policy.")
        if "Permissions-Policy" not in headers:
            add("headers.permissions", "Missing Permissions Policy", "info", "No Permissions-Policy header was observed.",
                "Disable unused browser capabilities, for example camera=(), microphone=(), geolocation=().")
    if headers.get("Access-Control-Allow-Origin", "").strip() == "*":
        add("cors.wildcard", "Review wildcard CORS access", "low", "This response allows any origin to read public, non-credentialed responses. This may be intentional.",
            "Use an explicit origin allowlist for private APIs; retain wildcard access only for intentionally public resources.", confidence="medium")
    if re.search(r"\d+\.\d+", headers.get("Server", "")) or headers.get("X-Powered-By"):
        add("headers.disclosure", "Technology information disclosure", "info", "Response headers disclose implementation details.",
            "Remove unnecessary Server version and X-Powered-By headers.")

    # Expires contains commas; never split Set-Cookie on commas.
    for raw in headers.getall("Set-Cookie", []):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            continue
        for name, morsel in cookie.items():
            issues = []
            if not morsel["secure"]:
                issues.append("Secure is missing")
            if not morsel["httponly"]:
                issues.append("HttpOnly is missing (may be intentional for JavaScript-readable cookies)")
            same_site = morsel["samesite"].lower()
            if same_site not in {"lax", "strict", "none"}:
                issues.append("SameSite is absent or invalid")
            if same_site == "none" and not morsel["secure"]:
                issues.append("SameSite=None requires Secure")
            if name.startswith("__Host-") and (morsel["domain"] or morsel["path"] != "/" or not morsel["secure"]):
                issues.append("__Host- prefix requirements are violated")
            if name.startswith("__Secure-") and not morsel["secure"]:
                issues.append("__Secure- prefix requires Secure")
            if issues:
                add("cookies.flags", "Review cookie security attributes", "medium", f"Cookie {name}: {'; '.join(issues)}. Values are omitted.",
                    "Use Secure, appropriate SameSite and HttpOnly for session cookies. Review each cookie's purpose before restricting script access.",
                    COOKIE_GUIDE, "medium", name)
    patterns = {
        "Private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "AWS access key identifier": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        "Slack webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+",
        "Discord webhook": r"https://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+",
    }
    for label, pattern in patterns.items():
        if re.search(pattern, text):
            add("exposure.secret", "Potential exposed secret", "high", f"A {label} pattern was found. The matched value is redacted; example values may be false positives.",
                "Verify ownership, revoke or rotate exposed credentials, remove them from public content and review access logs.",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html", "medium", label)
    service_key = bool(re.search(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b", text))
    # Decode only the JWT claims to identify a public service-role credential;
    # this is pattern detection, not signature verification or token use.
    for token in re.findall(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+\b", text):
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if isinstance(claims, dict) and claims.get("role") == "service_role":
                service_key = True
                break
        except (ValueError, UnicodeError):
            continue
    if service_key:
        add("exposure.service_key", "Potential public server-side service key", "high",
            "A Supabase-style secret key or JWT claiming service_role was found. Its value is omitted and validity was not tested.",
            "Rotate the key, remove it from public bundles and keep privileged credentials on the server.", confidence="medium")
    if re.search(r"you have an error in your sql syntax|SQLSTATE\[|psycopg2\.(?:errors|ProgrammingError)|ORA-\d{5}|sqlite3\.OperationalError", text, re.I):
        add("exposure.database_error", "Database error disclosure", "medium", "A recognizable database error is present; this does not prove SQL injection.",
            "Return generic errors to visitors, keep diagnostics in protected logs and use parameterized queries.", confidence="medium")
    if not is_html:
        return findings
    soup = BeautifulSoup(text, "html.parser")
    if soup.title and re.match(r"^Index of /", soup.title.get_text(strip=True), re.I):
        add("exposure.directory", "Possible directory listing", "medium", "The page title resembles an automatically generated directory index.",
            "Disable directory indexes and remove public access to backups and private files.", confidence="medium")
    if https:
        for tag in soup.find_all(["script", "img", "iframe", "link", "audio", "video", "source", "object"]):
            resource = tag.get("src") or tag.get("href") or tag.get("data")
            if isinstance(resource, str) and resource_scheme(url, resource) == "http":
                add("content.mixed", "Insecure resource on HTTPS page", "medium", "The HTML references at least one HTTP subresource. Browser upgrades and blocking require manual review.",
                    "Use HTTPS for all resources and remove insecure third-party dependencies.", confidence="medium")
                break
    for index, form in enumerate(soup.find_all("form", limit=50)):
        action_scheme = resource_scheme(url, form.get("action", ""))
        method = form.get("method", "get").lower()
        password = form.find("input", attrs={"type": re.compile("^password$", re.I)}) is not None
        if password and (not https or action_scheme != "https" or method == "get"):
            add("forms.password", "Insecure password form", "high", "A password form uses HTTP or submits through a GET URL.",
                "Serve login forms and their destinations over HTTPS and submit credentials with POST.", subject=str(index))
        elif https and action_scheme == "http":
            add("forms.transport", "Form submits over HTTP", "medium", "An HTTPS page submits form data to an unencrypted endpoint.",
                "Use an HTTPS form action.", subject=str(index))
        if method == "post" and not any(
            re.search(r"csrf|xsrf|authenticity|^_token$|requestverificationtoken", field.get("name", ""), re.I)
            for field in form.find_all("input")
        ):
            add("forms.csrf", "Review form CSRF defenses", "low", "A POST form has no recognizable CSRF token field. Origin checks, SameSite cookies or JavaScript defenses may protect it.",
                "Verify server-side CSRF defenses; protect state-changing requests with tokens or an appropriate equivalent.",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html", "low", str(index))
    return findings
