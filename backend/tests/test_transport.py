"""Exercise the real HTTP client against a controlled local fixture.

Only this test replaces DNS policy to map a public-looking hostname to the
fixture. Production has no private-address override.
"""
import asyncio
import socket

import aiohttp
from aiohttp import web

from scanner import WebSecurityScanner


def test_real_http_crawl_and_report(monkeypatch):
    async def run():
        hits = []
        async def page(request):
            hits.append(request.path_qs)
            if request.path == "/":
                return web.Response(text='<a href="/next?token=PRIVATE_VALUE">next</a><a href="http://outside.example/">outside</a>', content_type="text/html",
                                    headers={"Set-Cookie": "session=PRIVATE_COOKIE; SameSite=None"})
            return web.Response(text='<form method="post"><input type="password"></form>', content_type="text/html")
        application = web.Application()
        application.router.add_get("/{path:.*}", page)
        runner = web.AppRunner(application)
        await runner.setup()
        server_socket = socket.socket()
        server_socket.bind(("127.0.0.1", 0))
        port = server_socket.getsockname()[1]
        site = web.SockSite(runner, server_socket)
        await site.start()

        class FixtureResolver(aiohttp.abc.AbstractResolver):
            async def resolve(self, host, port=0, family=socket.AF_INET):
                assert host == "example.com"
                return [dict(hostname=host, host="127.0.0.1", port=fixture_port, family=socket.AF_INET, proto=0, flags=0)]
            async def close(self):
                pass

        fixture_port = port
        monkeypatch.setattr("scanner.PublicResolver", FixtureResolver)
        try:
            report = await WebSecurityScanner("http://example.com", max_urls=2).scan_async()
        finally:
            await runner.cleanup()
        assert hits == ["/", "/next?token=PRIVATE_VALUE"]
        assert len(report["scanned_urls"]) == 2
        assert report["requests_made"] == 2
        assert "PRIVATE_VALUE" not in str(report)
        assert "PRIVATE_COOKIE" not in str(report)
        assert {"transport.http", "cookies.flags", "forms.password"} <= {f["code"] for f in report["vulnerabilities"]}
        assert report["summary"]["high"] >= 2
        assert all(f["fix_steps"] for f in report["vulnerabilities"])
    asyncio.run(run())
