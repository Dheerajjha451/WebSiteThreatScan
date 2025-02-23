import asyncio
import logging
import os
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Set

import aiohttp
import colorama
import requests
import requests.exceptions
import urllib3
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
from flask_cors import CORS

# Configure logging
log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

log_file = os.path.join(
    log_directory, f"security_scan_{datetime.now().strftime('%Y%m%d')}.log"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
)

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)


class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.timeout = ClientTimeout(total=10)
        colorama.init()

    @staticmethod
    def normalize_url(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    async def async_get(
        self, session: aiohttp.ClientSession, url: str, verify: bool = False
    ) -> tuple:
        try:
            async with session.get(url, ssl=verify, timeout=self.timeout) as response:
                return await response.text(), response.headers, response.status
        except Exception as e:
            logger.error("Error in async_get for %s: %s", url, str(e), exc_info=True)
            return None, None, None

    async def check_sql_injection_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    new_params = dict(params)
                    new_params[param] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment,
                        )
                    )
                    text, _, _ = await self.async_get(session, test_url)
                    if text and any(
                        error in text.lower()
                        for error in ["sql", "mysql", "sqlite", "postgresql", "oracle"]
                    ):
                        self.report_vulnerability(
                            {
                                "type": "SQL Injection",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                            }
                        )
            except Exception as e:
                logger.error(
                    "Error in SQL injection check for %s: %s",
                    url,
                    str(e),
                    exc_info=True,
                )

    async def check_xss_async(self, session: aiohttp.ClientSession, url: str) -> None:
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ]
        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    new_params = dict(params)
                    new_params[param] = [urllib.parse.quote(payload)]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment,
                        )
                    )
                    text, _, _ = await self.async_get(session, test_url)
                    if text and payload in text:
                        self.report_vulnerability(
                            {
                                "type": "Cross-Site Scripting (XSS)",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                            }
                        )
            except Exception as e:
                logger.error(
                    "Error in XSS check for %s: %s", url, str(e), exc_info=True
                )

    async def check_sensitive_info_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        sensitive_patterns = {
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "api_key": r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1',
        }
        try:
            text, _, _ = await self.async_get(session, url)
            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, text)
                for _ in matches:
                    self.report_vulnerability(
                        {
                            "type": "Sensitive Information Exposure",
                            "url": url,
                            "info_type": info_type,
                            "pattern": pattern,
                        }
                    )
        except Exception as e:
            logger.error(
                "Error checking sensitive information on %s: %s",
                url,
                str(e),
                exc_info=True,
            )

    async def check_csrf_async(self, session: aiohttp.ClientSession, url: str) -> None:
        try:
            text, _, _ = await self.async_get(session, url)
            soup = BeautifulSoup(text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                tokens = form.find_all(
                    "input", {"name": ["csrf_token", "csrfmiddlewaretoken", "_token"]}
                )
                if not tokens and form.get("action"):
                    self.report_vulnerability(
                        {
                            "type": "Potential CSRF Vulnerability",
                            "url": url,
                            "details": "Missing CSRF token in form",
                        }
                    )
        except Exception as e:
            logger.error("Error checking CSRF on %s: %s", url, str(e), exc_info=True)

    async def check_insecure_cookies_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        try:
            _, headers, _ = await self.async_get(session, url)
            cookies = headers.get("Set-Cookie", "").split(",")
            for cookie in cookies:
                issues = []
                if "Secure" not in cookie:
                    issues.append("Secure flag missing")
                if "HttpOnly" not in cookie:
                    issues.append("HttpOnly flag missing")
                if (
                    "Domain" in cookie
                    and "session" in cookie.lower()
                    and "Domain" not in urllib.parse.urlparse(url).netloc
                ):
                    issues.append("Potential session cookie misconfiguration")
                if issues:
                    self.report_vulnerability(
                        {
                            "type": "Insecure Cookie Settings",
                            "url": url,
                            "cookie_name": cookie.split("=")[0],
                            "issues": ", ".join(issues),
                        }
                    )
        except Exception as e:
            logger.error("Error checking cookies on %s: %s", url, str(e), exc_info=True)

    async def check_directory_traversal_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        payloads = [
            "../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "..%5c..%5cwindows%5cwin.ini",
        ]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in payloads:
                    new_params = dict(params)
                    new_params[param] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment,
                        )
                    )
                    text, _, _ = await self.async_get(session, test_url)
                    if text and any(
                        indicator in text.lower()
                        for indicator in [
                            "root:x:",
                            "[extensions]",
                            "for 16-bit app support",
                        ]
                    ):
                        self.report_vulnerability(
                            {
                                "type": "Directory Traversal",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                            }
                        )
        except Exception as e:
            logger.error(
                "Error testing directory traversal on %s: %s",
                url,
                str(e),
                exc_info=True,
            )

    async def check_security_headers_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        important_headers = {
            "Content-Security-Policy": "Missing CSP header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "Strict-Transport-Security": "Missing HSTS header",
            "X-XSS-Protection": "Missing X-XSS-Protection header",
        }
        try:
            _, headers, _ = await self.async_get(session, url)
            missing = [
                msg
                for header, msg in important_headers.items()
                if header not in headers
            ]
            if missing:
                self.report_vulnerability(
                    {
                        "type": "Security Headers Missing",
                        "url": url,
                        "details": ", ".join(missing),
                    }
                )
        except Exception as e:
            logger.error(
                "Error checking security headers on %s: %s", url, str(e), exc_info=True
            )

    async def check_command_injection_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        payloads = ["; ls", "| dir", "`id`", "$(whoami)"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in payloads:
                    new_params = dict(params)
                    new_params[param] = [urllib.parse.quote(payload)]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment,
                        )
                    )
                    text, _, _ = await self.async_get(session, test_url)
                    if text and any(
                        indicator in text.lower()
                        for indicator in [
                            "root:",
                            "uid=",
                            "volume in drive",
                            "Directory of",
                        ]
                    ):
                        self.report_vulnerability(
                            {
                                "type": "Command Injection",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                            }
                        )
        except Exception as e:
            logger.error(
                "Error testing command injection on %s: %s", url, str(e), exc_info=True
            )

    async def check_exposed_webhooks_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        webhook_patterns = {
            "Discord": r"https://discord.com/api/webhooks/\d+/[a-zA-Z0-9_-]+",
            "Slack": r"https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+",
            "Telegram": r"https://api.telegram.org/bot[A-Za-z0-9:_]+/sendMessage",
            "GitHub": r"https://github.com/webhooks/.*",
            "Stripe": r"https://api.stripe.com/v1/[a-zA-Z0-9_/]+",
            "Twilio": r"https://api.twilio.com/2010-04-01/Accounts/[A-Za-z0-9]+/.*",
        }
        try:
            text, _, _ = await self.async_get(session, url)
            for service, pattern in webhook_patterns.items():
                matches = re.findall(pattern, text)
                for match in matches:
                    self.report_vulnerability(
                        {
                            "type": "Exposed Webhook",
                            "url": url,
                            "service": service,
                            "exposed_url": match,
                        }
                    )
        except Exception as e:
            logger.error(
                "Error checking exposed webhooks on %s: %s", url, str(e), exc_info=True
            )

    async def check_ssl_tls_async(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme != "https":
                self.report_vulnerability(
                    {
                        "type": "Insecure Protocol",
                        "url": url,
                        "details": "The website is not using HTTPS.",
                    }
                )
            else:
                _, _, status = await self.async_get(session, url, verify=True)
                if status == 200:
                    logger.info("The website %s is SSL/TLS certified.", url)
                else:
                    self.report_vulnerability(
                        {
                            "type": "SSL/TLS Certification Issue",
                            "url": url,
                            "details": "The website responded with status code %d."
                            % status,
                        }
                    )
        except Exception as e:
            logger.error(
                "Error in SSL/TLS check for %s: %s", url, str(e), exc_info=True
            )

    async def scan_async(self) -> List[Dict]:
        self.visited_urls = set()
        self.vulnerabilities = []

        # First crawl synchronously (or implement async crawling if needed)
        self.crawl(self.target_url)

        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in self.visited_urls:
                tasks.extend(
                    [
                        self.check_sql_injection_async(session, url),
                        self.check_xss_async(session, url),
                        self.check_sensitive_info_async(session, url),
                        self.check_csrf_async(session, url),
                        self.check_insecure_cookies_async(session, url),
                        self.check_directory_traversal_async(session, url),
                        self.check_security_headers_async(session, url),
                        self.check_command_injection_async(session, url),
                        self.check_exposed_webhooks_async(session, url),
                        self.check_ssl_tls_async(session, url),
                    ]
                )

            # Run all checks concurrently
            await asyncio.gather(*tasks, return_exceptions=True)

        return self.vulnerabilities

    def scan(self) -> List[Dict]:
        return asyncio.run(self.scan_async())

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return
        try:
            self.visited_urls.add(url)
            response = requests.get(url, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a", href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link["href"])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        except Exception as e:
            logger.error("Error crawling %s: %s", url, str(e), exc_info=True)

    def report_vulnerability(self, vulnerability: Dict) -> None:
        self.vulnerabilities.append(vulnerability)
        logger.warning("Vulnerability Found:")
        for key, value in vulnerability.items():
            logger.warning("%s: %s", key, value)
        logger.warning("%s", "-" * 50)


async def async_scan_endpoint():
    try:
        data = request.get_json()
        target_url = data.get("url")
        if not target_url:
            logger.error("URL parameter missing in request")
            return jsonify({"error": "URL is required"}), 400

        logger.info("Starting security scan for: %s", target_url)
        scanner = WebSecurityScanner(target_url)
        vulnerabilities = await scanner.scan_async()

        response_data = {
            "vulnerabilities": vulnerabilities,
            "scanned_urls": list(scanner.visited_urls),
        }

        if not vulnerabilities:
            logger.info("Scan completed. No vulnerabilities found.")
            response_data["message"] = "No vulnerabilities found."
        else:
            logger.info(
                "Scan completed. Found %d vulnerabilities.", len(vulnerabilities)
            )

        return jsonify(response_data), 200
    except Exception as e:
        logger.error("Error during scan: %s", str(e), exc_info=True)
        return jsonify({"error": str(e)}), 500


def scan_endpoint():
    return asyncio.run(async_scan_endpoint())


if __name__ == "__main__":
    logger.info("Starting Web Security Scanner application")
    app.run(debug=True, host="127.0.0.1", port=5000)
