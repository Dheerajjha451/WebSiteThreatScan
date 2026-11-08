import base64
import json

from multidict import CIMultiDict

from checks import analyze_page
from guidance import GUIDANCE


def secure_headers():
    return CIMultiDict({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'", "Strict-Transport-Security": "max-age=31536000",
                         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin",
                         "Permissions-Policy": "camera=()"})


def test_hardened_page_has_no_findings():
    assert analyze_page("https://example.com/", "<h1>Hello</h1>", secure_headers(), True) == []


def test_cookie_expiry_commas_and_case_do_not_create_false_cookies():
    headers = secure_headers()
    headers.add("Set-Cookie", "session=PRIVATE; expires=Wed, 09 Jun 2027 10:18:14 GMT; secure; httponly; samesite=Lax; path=/")
    headers.add("Set-Cookie", "preferences=PRIVATE; Secure; HttpOnly; SameSite=Strict")
    assert not analyze_page("https://example.com", "", headers, True)
    assert not analyze_page("https://example.com", "", secure_headers(), True)


def test_cookie_flags_and_secrets_are_redacted_with_guidance():
    headers = secure_headers()
    headers.add("Set-Cookie", "__Host-session=PRIVATE_COOKIE_VALUE; SameSite=None; Domain=example.com")
    findings = analyze_page("https://example.com/?token=PRIVATE_QUERY", "AKIAABCDEFGHIJKLMNOP", headers, True)
    output = json.dumps(findings)
    for secret in ["PRIVATE_COOKIE_VALUE", "PRIVATE_QUERY", "AKIAABCDEFGHIJKLMNOP"]:
        assert secret not in output
    assert {f["code"] for f in findings} == {"cookies.flags", "exposure.secret"}
    assert "prefix" in findings[0]["details"]
    assert all(f["severity_reason"] and len(f["fix_steps"]) >= 2 and f["verification"] for f in findings)


def test_form_method_and_tokens_avoid_false_csrf_findings():
    html = '<form action="/search"><input name="q"></form><form method="post"><input name="authenticity_token"></form>'
    assert not analyze_page("https://example.com", html, secure_headers(), True)


def test_mixed_content_password_forms_and_csrf():
    html = '<script src="http://cdn.example.com/a.js"></script><form method="get"><input type="password"></form><form method="post" action="http://example.com"></form>'
    codes = {f["code"] for f in analyze_page("https://example.com", html, secure_headers(), True)}
    assert codes == {"content.mixed", "forms.password", "forms.transport", "forms.csrf"}


def test_database_mentions_are_not_injection_findings():
    assert not analyze_page("https://example.com/", "Learn SQL, MySQL and PostgreSQL", secure_headers(), True)
    findings = analyze_page("https://example.com/", "SQLSTATE[42000]: syntax error", secure_headers(), True)
    assert findings[0]["code"] == "exposure.database_error"
    assert "does not prove SQL injection" in findings[0]["details"]


def test_non_html_does_not_need_html_specific_headers():
    assert not analyze_page("https://example.com/api", '{}', secure_headers(), False)


def test_malformed_html_resources_do_not_crash():
    analyze_page("https://example.com/", '<img src="http://[bad"><form action="http://[bad"><input type=password></form>', secure_headers(), True)


def test_service_role_jwt_flagged_but_public_anon_key_is_not():
    def token(role):
        payload = base64.urlsafe_b64encode(json.dumps({"role": role}).encode()).decode().rstrip("=")
        return "eyJhbGciOiJIUzI1NiJ9." + payload + ".signature"
    secret = token("service_role")
    findings = analyze_page("https://example.com/", secret, secure_headers(), True)
    assert findings[0]["code"] == "exposure.service_key"
    assert secret not in json.dumps(findings)
    assert not analyze_page("https://example.com/", token("anon"), secure_headers(), True)


def test_every_passive_check_has_an_explanation():
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).parents[1] / "checks.py").read_text())
    codes = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "add"}
    assert codes == set(GUIDANCE)
