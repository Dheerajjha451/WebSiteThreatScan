import asyncio

import pytest
from multidict import CIMultiDict

from scanner import MAX_BODY_BYTES, WebSecurityScanner
from targets import UnsafeTarget


class Content:
    def __init__(self, body):
        self.body = body

    async def iter_chunked(self, size):
        for offset in range(0, len(self.body), size):
            yield self.body[offset:offset + size]


class Response:
    def __init__(self, body=b"<h1>Page</h1>", status=200, headers=None):
        self.status = status
        self.headers = CIMultiDict(headers or {"Content-Type": "text/html"})
        self.charset = "utf-8"
        self.content = Content(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class Session:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.pages[url]


def test_fetch_blocks_cross_host_redirect_before_request():
    scanner = WebSecurityScanner("https://example.com")
    session = Session({"https://example.com/": Response(status=302, headers={"Location": "https://example.com.evil.com/"})})
    with pytest.raises(UnsafeTarget):
        asyncio.run(scanner.fetch(session, scanner.target_url))
    assert len(session.calls) == 1
    assert session.calls[0][1] == {"allow_redirects": False}


@pytest.mark.parametrize("destination", ["http://127.0.0.1", "http://169.254.169.254/", "file:///etc/passwd", "http://example.com/"])
def test_fetch_blocks_internal_and_downgrade_redirects(destination):
    scanner = WebSecurityScanner("https://example.com")
    session = Session({"https://example.com/": Response(status=302, headers={"Location": destination})})
    with pytest.raises(UnsafeTarget):
        asyncio.run(scanner.fetch(session, scanner.target_url))
    assert len(session.calls) == 1


def test_http_upgrade_and_non_200_success_work():
    scanner = WebSecurityScanner("http://example.com")
    session = Session({"http://example.com/": Response(status=301, headers={"Location": "https://example.com/"}), "https://example.com/": Response(status=201)})
    page = asyncio.run(scanner.fetch(session, scanner.target_url))
    assert page[0] == "https://example.com/"
    assert scanner.requests_made == 2


def test_loop_and_size_limits_are_reported():
    scanner = WebSecurityScanner("https://example.com")
    session = Session({"https://example.com/": Response(status=302, headers={"Location": "/"})})
    assert asyncio.run(scanner.fetch(session, scanner.target_url)) is None
    assert scanner.warnings[0]["code"] == "redirect_loop"
    scanner = WebSecurityScanner("https://example.com")
    session = Session({"https://example.com/": Response(body=b"a" * (MAX_BODY_BYTES + 100))})
    page = asyncio.run(scanner.fetch(session, scanner.target_url))
    assert len(page[1]) == MAX_BODY_BYTES
    assert scanner.warnings[0]["code"] == "body_limit"


def test_same_host_bounded_crawl_preserves_queries_and_deduplicates():
    root = '<a href="/search?q=one">one</a><a href="/search?q=two#x">two</a><a href="/search?q=one">duplicate</a><a href="https://example.com.evil.com">outside</a><a href="/extra">limit</a>'
    session = Session({"https://example.com/": Response(body=root.encode()), "https://example.com/search?q=one": Response(), "https://example.com/search?q=two": Response()})
    scanner = WebSecurityScanner("https://example.com", max_urls=3)
    asyncio.run(scanner.crawl(session))
    assert len(scanner.scanned_urls) == 3
    assert len(session.calls) == 3
    assert scanner.url_limit_exceeded
    assert "https://example.com/search?q=one" in scanner.visited_urls
    assert "https://example.com/search?q=two" in scanner.visited_urls
    assert all("one" not in f["url"] for f in scanner.vulnerabilities)
    assert len({f["id"] for f in scanner.vulnerabilities}) == len(scanner.vulnerabilities)


def test_failed_response_not_counted_as_analyzed():
    scanner = WebSecurityScanner("https://example.com")
    session = Session({"https://example.com/": Response(status=403)})
    asyncio.run(scanner.crawl(session))
    assert not scanner.scanned_urls
    assert not scanner.vulnerabilities
    assert scanner.warnings[0]["code"] == "http_error"


def test_overall_deadline_returns_partial_report(monkeypatch):
    scanner = WebSecurityScanner("https://example.com", max_time=.01)
    async def slow(_session):
        await asyncio.sleep(1)
    monkeypatch.setattr(scanner, "crawl", slow)
    report = scanner.scan()
    assert report["time_limit_exceeded"]
    assert not report["complete"]
    assert report["summary"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def test_request_budget_stops_fetch():
    scanner = WebSecurityScanner("https://example.com")
    scanner.requests_made = 60
    session = Session({})
    assert asyncio.run(scanner.fetch(session, scanner.target_url)) is None
    assert scanner.request_limit_exceeded
    assert not session.calls
