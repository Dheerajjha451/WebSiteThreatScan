"""Human-readable impact, repair choices and verification for every check."""

GUIDANCE = {
    "exposure.service_key": (
        "High: privileged service keys can bypass normal authorization or database policies if valid. A public JWT claim or key pattern alone does not confirm authenticity or current validity.",
        ["Locate the exposed key without copying it into logs or tickets.", "Rotate or revoke the server-side key in the provider dashboard and review access logs.", "Keep privileged keys in server-only configuration; remove them from public bundles, HTML and caches.", "Use publishable or anon keys only with tested authorization policies for browser access; those public keys are not service-role secrets."],
        "Confirm the old credential is revoked, public content contains no privileged key, and ordinary client access still respects database policies."),
    "transport.http": (
        "High: HTTP traffic can be read or altered by someone on the network, including credentials and page content.",
        ["Install a trusted TLS certificate at your hosting provider, CDN or reverse proxy.", "Serve every page and form over HTTPS, then configure permanent HTTP-to-HTTPS redirects.", "Update internal links and resource URLs; enable HSTS once HTTPS is reliable."],
        "Open the HTTP URL and confirm it redirects to HTTPS with a valid certificate."),
    "headers.hsts": (
        "Medium: browsers are not explicitly instructed to require HTTPS on later visits, leaving downgrade opportunities. Missing HSTS alone does not prove an attack.",
        ["Confirm your site works entirely over HTTPS.", "Add Strict-Transport-Security with a short positive max-age, then increase it after testing.", "Choose includeSubDomains only when all subdomains support HTTPS; evaluate preload separately."],
        "Inspect an HTTPS response for one valid positive max-age directive, then rescan."),
    "headers.nosniff": (
        "Low: MIME sniffing can cause uploaded or mislabeled files to be interpreted as executable content; impact depends on the content served.",
        ["Set accurate Content-Type values for every response.", "Add X-Content-Type-Options: nosniff at your application or reverse proxy.", "Check that scripts and styles still load without MIME type errors."],
        "Confirm the response has X-Content-Type-Options: nosniff."),
    "headers.csp": (
        "Medium: the page lacks an enforced browser restriction on script sources. CSP reduces the impact of some injection bugs; its absence does not establish XSS.",
        ["Inventory required scripts, styles, frames and other resources.", "Test a restrictive policy in Content-Security-Policy-Report-Only first.", "Use nonces or hashes for necessary inline scripts and restrict allowed origins.", "Move the tested policy to Content-Security-Policy and monitor violations."],
        "Confirm the enforced header exists and required pages work without unexpected CSP violations."),
    "headers.csp_weak": (
        "Medium: broad script permissions can reduce CSP's ability to contain injected scripts. Nonces, strict-dynamic and browser support can change the effective protection.",
        ["Review the effective script-src and fallback default-src policies in browser developer tools.", "Replace wildcard, data:, unsafe-inline and unsafe-eval allowances where possible.", "Choose per-response nonces or script hashes for required inline code.", "Test in report-only mode before enforcing the revised policy."],
        "Review the effective browser policy and rescan; this heuristic may still flag intentionally supported fallback directives."),
    "headers.framing": (
        "Medium: other sites may embed this page and trick users into interacting with it. Impact depends on whether sensitive actions exist.",
        ["Decide which sites, if any, must embed your page.", "Set CSP frame-ancestors 'none' to disallow embedding, or 'self' / explicit origins for required embeds.", "Alternatively set X-Frame-Options: DENY or SAMEORIGIN for a simple policy.", "Test legitimate embeds and sensitive actions."],
        "Confirm the header is present and an unauthorized cross-origin iframe is blocked."),
    "headers.referrer": (
        "Low: an absent or permissive explicit policy can expose browsing details in Referer headers. Modern browser defaults may already reduce exposure.",
        ["Choose strict-origin-when-cross-origin for a general privacy-preserving default, or no-referrer for stricter privacy.", "Set Referrer-Policy on HTML responses at your app or reverse proxy.", "Keep credentials and personal information out of URLs regardless of policy."],
        "Inspect outgoing Referer headers when following a link to another origin."),
    "headers.permissions": (
        "Info: this is a hardening opportunity. Missing Permissions-Policy does not establish that browser capabilities are exposed without user consent.",
        ["List which browser features your site actually needs.", "Disable unused features, for example Permissions-Policy: camera=(), microphone=(), geolocation=().", "Allow required origins for features your app uses and test those flows."],
        "Confirm the header exists and required browser features still work."),
    "cors.wildcard": (
        "Low: any site can read this response without credentials. This is expected for public content; browsers do not allow wildcard origins with credentialed reads.",
        ["Determine whether the response is intentionally public; if so, wildcard CORS may need no change.", "For private APIs, use an exact origin allowlist rather than reflecting arbitrary origins.", "Keep authentication and authorization on every private endpoint; CORS is not access control."],
        "Try allowed and untrusted Origin headers and check both CORS headers and server-side authorization."),
    "headers.disclosure": (
        "Info: technology details can help reconnaissance, but a disclosed version alone does not prove a vulnerable component.",
        ["Remove unnecessary X-Powered-By and server version headers in your app or proxy.", "Keep the underlying software patched; hiding headers does not replace updates."],
        "Inspect public response headers and verify unnecessary version details are gone."),
    "cookies.flags": (
        "Medium: cookie attributes may allow transport exposure, JavaScript access or cross-site delivery. Actual impact depends on whether the cookie is sensitive.",
        ["Identify the cookie's owner and whether it carries a session or authentication value.", "Enable Secure for HTTPS cookies and HttpOnly for sensitive cookies that scripts do not need.", "Choose SameSite=Lax or Strict where possible; cross-site cookies need SameSite=None; Secure.", "For __Host- cookies, use Secure, Path=/ and no Domain; __Secure- cookies need Secure.", "Retest login, logout and legitimate embedded or cross-site flows."],
        "Inspect each Set-Cookie separately in developer tools; confirm required flags and working session flows."),
    "exposure.secret": (
        "High: the page contains a credential-like pattern that could allow unauthorized service access. Example or inactive values can be false positives, so manual verification is required.",
        ["Locate the pattern in your source or response without reposting it in tickets or chat.", "If real, revoke or rotate the credential immediately at its provider.", "Move secrets to server-side configuration and remove them from public bundles and history where appropriate.", "Review provider audit logs, reduce permissions and rescan the public page."],
        "Confirm the old credential is revoked and no credential value remains in publicly served content."),
    "exposure.database_error": (
        "Medium: database errors reveal internal details that can assist attacks. This check observes existing text and does not establish SQL injection.",
        ["Return a generic error page or structured error to clients.", "Send detailed diagnostics to protected server logs with secret redaction.", "Use parameterized queries and independently test database input handling in an authorized environment."],
        "Reproduce the original error condition and confirm no database diagnostics reach the visitor."),
    "exposure.directory": (
        "Medium: a directory index can reveal files or backups that were not intended for visitors. The title match is heuristic and may be an intentional page.",
        ["Verify whether the response is an actual server-generated listing.", "Disable directory autoindex in your web server or restrict the directory.", "Remove backups, configuration files and private artifacts from the web root."],
        "Request the directory and confirm it shows intended content or denies access without listing private files."),
    "content.mixed": (
        "Medium: HTTP resources on an HTTPS page can weaken integrity or break when browsers block them. Browser upgrades or CSP may already prevent loading.",
        ["Use browser developer tools to find HTTP resource references and their actual loading behavior.", "Replace them with HTTPS URLs; upgrade or remove providers that lack HTTPS.", "Review CSS and script-generated resource URLs as well, which this HTML check cannot inspect."],
        "Reload the page and confirm there are no HTTP subresource references or mixed-content warnings."),
    "forms.password": (
        "High: a password form uses HTTP or GET, potentially exposing credentials to the network, URL history, logs or referrers.",
        ["Serve both the form page and its action URL over HTTPS.", "Set method=post and ensure the server accepts credentials only in the request body.", "Remove credentials from logs and analytics; consider resetting credentials if exposure occurred.", "Retest authentication and HTTPS redirects."],
        "Use developer tools to confirm passwords are sent in a POST body over HTTPS and never in a URL."),
    "forms.transport": (
        "Medium: an HTTPS page sends form data to HTTP, where it can be intercepted or modified. Impact depends on the data submitted.",
        ["Change the form action to an HTTPS endpoint.", "Ensure the endpoint's certificate is valid and its redirects remain on HTTPS.", "Retest submission, validation and errors."],
        "Inspect form submissions and confirm every hop uses HTTPS."),
    "forms.csrf": (
        "Low: no recognizable token was found in a POST form. SameSite cookies, Origin checks or JavaScript may already protect it, so this is a review prompt.",
        ["Identify whether the form performs an authenticated state-changing action.", "Review server-side CSRF protection and framework middleware.", "Use a validated CSRF token or an appropriate equivalent such as strict Origin validation; configure SameSite cookies as additional protection.", "Test missing and invalid tokens or untrusted origins in an authorized environment."],
        "Confirm a forged cross-site submission cannot change state; a token field alone is not proof of protection."),
}


def explain(finding):
    reason, steps, verification = GUIDANCE[finding["code"]]
    return dict(finding, severity_reason=reason, fix_steps=steps, verification=verification)
