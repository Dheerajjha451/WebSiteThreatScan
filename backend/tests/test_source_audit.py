import json
import subprocess

from source_audit import source_audit


def write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def test_detects_user_examples_without_disclosing_code_or_secrets(tmp_path):
    write(tmp_path, "app/api/auth/signup/route.ts", 'const {role} = await request.json(); profiles.insert({role: role || "customer"});')
    write(tmp_path, "app/api/auth/verify-email/route.ts", 'const {email} = await request.json(); update({email_verified: true, email_confirm: true});')
    write(tmp_path, "app/api/auth/request-password-reset/route.ts", 'return json({error: "No account found for this email."}, {status:404});')
    write(tmp_path, "app/api/pdf/render/route.ts", 'const {html} = await request.json(); const browser = await chromium.launch({args:["--no-sandbox"]}); await page.setContent(html);')
    write(tmp_path, "lib/client/browserCookieStorage.ts", 'const access_token = "PRIVATE_TOKEN"; document.cookie = access_token;')
    write(tmp_path, "app/api/send-order-email/route.ts", 'const {to, name} = await request.json(); await transporter.sendMail({to, html: `<p>${name}</p>`});')
    write(tmp_path, "Dockerfile", 'FROM node:24\nCMD ["node", "server.js"]')
    write(tmp_path, "lib/server.ts", 'const secret = process.env.SUPABASE_SERVICE_ROLE_KEY; const password = process.env.SMTP_PASS;')
    write(tmp_path, ".env.example", "OBSERVABILITY_TOKEN=placeholder")
    write(tmp_path, ".env", "ACTUAL_SECRET=DO_NOT_READ")
    report = source_audit(tmp_path)
    codes = {f["code"] for f in report["vulnerabilities"]}
    assert codes == {"source.signup_role", "source.email_verification", "source.account_enumeration", "source.browser_sandbox", "source.browser_input", "source.browser_capacity", "source.auth_cookie", "source.email_authorization", "source.email_html", "source.endpoint_rate", "source.container_user", "source.env_docs"}
    output = json.dumps(report)
    assert "PRIVATE_TOKEN" not in output and "ACTUAL_SECRET" not in output and "DO_NOT_READ" not in output
    assert report["summary"]["critical"] == 2
    assert report["mode"] == "source" and not report["complete"]
    assert all(f["severity_reason"] and f["fix_steps"] and f["verification"] for f in report["vulnerabilities"])


def test_recognizes_visible_controls_and_final_docker_stage(tmp_path):
    write(tmp_path, "app/api/auth/signup/route.ts", 'const {email} = await request.json(); profiles.insert({role: "customer"});')
    write(tmp_path, "app/api/auth/verify-email/route.ts", 'await supabase.auth.verifyOtp({token_hash, type:"email"}); update({email_verified:true});')
    write(tmp_path, "app/api/send-email/route.ts", 'await requireAuth(); rateLimit(); transporter.sendMail({html: escapeHtml(name)});')
    write(tmp_path, "Dockerfile", 'FROM node:24 AS build\nUSER root\nFROM node:24\nUSER node\nCMD ["node", "app.js"]')
    assert not source_audit(tmp_path)["vulnerabilities"]
    write(tmp_path, "Dockerfile", 'FROM node:24 AS build\nUSER node\nFROM node:24\nCMD ["node", "app.js"]')
    assert source_audit(tmp_path)["vulnerabilities"][0]["code"] == "source.container_user"


def test_skips_symlinks_generated_code_and_real_environment_files(tmp_path):
    write(tmp_path, "node_modules/bad.ts", 'document.cookie = "session";')
    write(tmp_path, ".env.local", "secret=sensitive")
    (tmp_path / "linked.ts").symlink_to("/etc/passwd")
    write(tmp_path, "large.ts", "x" * 524_289)
    report = source_audit(tmp_path)
    assert not report["scanned_urls"]
    assert report["warnings"][0]["code"] == "file_limit"


def test_npm_audit_is_explicit_and_does_not_run_scripts(tmp_path, monkeypatch):
    write(tmp_path, "package-lock.json", "{}")
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, json.dumps({"vulnerabilities": {"some-package": {"severity": "moderate", "range": "<2.0.0"}}}), "")
    monkeypatch.setattr("source_audit.shutil.which", lambda _: "/usr/bin/npm")
    monkeypatch.setattr("source_audit.subprocess.run", run)
    report = source_audit(tmp_path)
    assert not calls and report["warnings"][0]["code"] == "audit_not_run"
    report = source_audit(tmp_path, npm_audit=True)
    assert "--ignore-scripts" in calls[0] and "--package-lock-only" in calls[0]
    assert report["vulnerabilities"][0]["severity"] == "medium"


def test_failed_advisory_lookup_never_claims_clean_dependencies(tmp_path, monkeypatch):
    write(tmp_path, "package-lock.json", "{}")
    monkeypatch.setattr("source_audit.shutil.which", lambda _: "/usr/bin/npm")
    monkeypatch.setattr("source_audit.subprocess.run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, '{"error":{}}', ""))
    report = source_audit(tmp_path, npm_audit=True)
    assert report["warnings"][0]["code"] == "audit_failed"
