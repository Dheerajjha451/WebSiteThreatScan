"""Bounded, anonymous, same-host passive crawler."""
import asyncio
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import aiohttp
from bs4 import BeautifulSoup

from checks import analyze_page
from targets import PublicResolver, UnsafeTarget, in_scope, normalize_url, redact_url

MAX_BODY_BYTES = 1_048_576
MAX_REQUESTS = 60
MAX_REDIRECTS = 5


class WebSecurityScanner:
    def __init__(self, target_url, max_depth=2, max_urls=10, max_time=50):
        self.target_url = normalize_url(target_url)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_time = max_time
        self.visited_urls = set()
        self.scanned_urls = []
        self.vulnerabilities = []
        self.warnings = []
        self.url_limit_exceeded = False
        self.time_limit_exceeded = False
        self.request_limit_exceeded = False
        self.requests_made = 0
        self._finding_ids = set()
        self._fetched_urls = set()

    def warn(self, code, url, message):
        self.warnings.append(dict(code=code, url=redact_url(url), message=message))

    async def fetch(self, session, url):
        current = url
        for hop in range(MAX_REDIRECTS + 1):
            current = normalize_url(current)
            if not in_scope(self.target_url, current):
                raise UnsafeTarget("Cross-host redirects and HTTPS downgrades are blocked.")
            if self.requests_made >= MAX_REQUESTS:
                self.request_limit_exceeded = True
                self.warn("request_limit", current, "The outbound request budget was reached.")
                return None
            if current in self._fetched_urls:
                return None
            self._fetched_urls.add(current)
            self.requests_made += 1
            async with session.get(current, allow_redirects=False) as response:
                if response.status in {301, 302, 303, 307, 308}:
                    if not response.headers.get("Location"):
                        self.warn("redirect_invalid", current, "A redirect had no Location header.")
                        return None
                    if hop == MAX_REDIRECTS:
                        self.warn("redirect_limit", current, "The redirect limit was reached.")
                        return None
                    destination = normalize_url(urljoin(current, response.headers["Location"]))
                    if urlsplit(current).scheme == "https" and urlsplit(destination).scheme == "http":
                        raise UnsafeTarget("HTTPS to HTTP redirects are blocked.")
                    if destination in self._fetched_urls:
                        self.warn("redirect_loop", current, "The redirect points to an already fetched URL.")
                        return None
                    current = destination
                    continue
                if not 200 <= response.status < 300:
                    self.warn("http_error", current, f"The target returned HTTP {response.status}; the page was not analyzed.")
                    return None
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
                is_html = content_type in {"text/html", "application/xhtml+xml"}
                if not (is_html or content_type.startswith("text/") or content_type in {"application/json", "application/javascript"}):
                    self.warn("unsupported_content", current, "Non-text response skipped.")
                    return None
                body = bytearray()
                async for chunk in response.content.iter_chunked(65_536):
                    body.extend(chunk[:MAX_BODY_BYTES + 1 - len(body)])
                    if len(body) > MAX_BODY_BYTES:
                        self.warn("body_limit", current, "Response exceeded 1 MiB; only the initial content was analyzed.")
                        del body[MAX_BODY_BYTES:]
                        break
                try:
                    text = body.decode(response.charset or "utf-8", errors="replace")
                except LookupError:
                    text = body.decode("utf-8", errors="replace")
                return current, text, response.headers, is_html
        return None

    async def crawl(self, session):
        queue = deque([(self.target_url, 0)])
        queued = {self.target_url}
        while queue:
            if len(self.visited_urls) >= self.max_urls:
                self.url_limit_exceeded = True
                break
            url, depth = queue.popleft()
            if url in self._fetched_urls:
                continue
            self.visited_urls.add(url)
            try:
                page = await self.fetch(session, url)
            except UnsafeTarget as exc:
                self.warn("target_blocked", url, str(exc))
                continue
            except aiohttp.ClientSSLError:
                self.warn("tls_error", url, "TLS certificate or handshake validation failed; verification was not bypassed.")
                continue
            except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
                self.warn("fetch_error", url, "Could not fetch the page within the request timeout.")
                continue
            if page is None:
                continue
            final_url, text, headers, is_html = page
            self.scanned_urls.append(redact_url(final_url))
            page_findings = analyze_page(final_url, text, headers, is_html)
            if len(page_findings) >= 100:
                self.warn("page_finding_limit", final_url, "The per-page 100-finding limit was reached; additional observations may have been omitted.")
            for finding in page_findings:
                if finding["id"] not in self._finding_ids:
                    if len(self.vulnerabilities) >= 500:
                        if not any(w["code"] == "finding_limit" for w in self.warnings):
                            self.warn("finding_limit", final_url, "The 500-finding report limit was reached; additional findings were omitted.")
                        break
                    self._finding_ids.add(finding["id"])
                    self.vulnerabilities.append(finding)
            if not is_html:
                continue
            soup = BeautifulSoup(text, "html.parser")
            if len(soup.find_all("form", limit=51)) > 50:
                self.warn("form_limit", final_url, "Only the first 50 forms on this page were reviewed.")
            for link in soup.find_all("a", href=True):
                try:
                    candidate = normalize_url(urljoin(final_url, link["href"]))
                except (UnsafeTarget, ValueError):
                    continue
                if in_scope(self.target_url, candidate) and candidate not in queued and candidate not in self._fetched_urls:
                    if depth >= self.max_depth:
                        if not any(w["code"] == "depth_limit" for w in self.warnings):
                            self.warn("depth_limit", final_url, "Links beyond the configured crawl depth were skipped.")
                        continue
                    if len(queued) >= self.max_urls:
                        self.url_limit_exceeded = True
                        continue
                    queued.add(candidate)
                    queue.append((candidate, depth + 1))

    async def scan_async(self):
        started = time.monotonic()
        resolver = PublicResolver()
        try:
            connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, limit=2)
            async with aiohttp.ClientSession(
                connector=connector, timeout=aiohttp.ClientTimeout(total=10, connect=5),
                cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
                headers={"User-Agent": "WebsiteThreatScan/2.0 (passive security review)", "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8"},
                max_line_size=8192, max_field_size=8192,
            ) as session:
                try:
                    await asyncio.wait_for(self.crawl(session), timeout=self.max_time)
                except asyncio.TimeoutError:
                    self.time_limit_exceeded = True
                    self.warn("time_limit", self.target_url, "The total scan time limit was reached; results are partial.")
        finally:
            await resolver.close()
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.vulnerabilities.sort(key=lambda finding: (rank[finding["severity"]], finding["url"], finding["code"]))
        summary = {severity: sum(f["severity"] == severity for f in self.vulnerabilities) for severity in rank}
        complete = bool(self.scanned_urls) and not (self.warnings or self.url_limit_exceeded or self.time_limit_exceeded or self.request_limit_exceeded)
        return dict(schema_version=2, mode="passive", target=redact_url(self.target_url),
                    generated_at=datetime.now(timezone.utc).isoformat(),
                    vulnerabilities=self.vulnerabilities, scanned_urls=self.scanned_urls,
                    attempted_urls=len(self.visited_urls), requests_made=self.requests_made,
                    duration_seconds=round(time.monotonic() - started, 2), summary=summary,
                    complete=complete, warnings=self.warnings,
                    url_limit_exceeded=self.url_limit_exceeded, time_limit_exceeded=self.time_limit_exceeded,
                    request_limit_exceeded=self.request_limit_exceeded,
                    limits=dict(max_urls=self.max_urls, max_depth=self.max_depth, max_time=self.max_time,
                                max_requests=MAX_REQUESTS, max_response_bytes=MAX_BODY_BYTES),
                    message="Passive checks finished. Findings need review; absence of findings does not establish security.")

    def scan(self):
        return asyncio.run(self.scan_async())
