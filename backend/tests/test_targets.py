import asyncio
from unittest.mock import AsyncMock

import pytest

from targets import PublicResolver, UnsafeTarget, in_scope, normalize_url, redact_url


@pytest.mark.parametrize("url", [
    "http://127.0.0.1", "http://10.0.0.1", "http://172.16.1.1", "http://192.168.0.1",
    "http://169.254.169.254/latest/meta-data", "http://100.64.0.1", "http://0.0.0.0",
    "http://[::1]", "http://[fd00::1]", "http://[fe80::1]", "http://[::ffff:8.8.8.8]",
    "http://[64:ff9b::808:808]", "http://[2002:0808:0808::1]", "http://224.0.0.1",
    "http://localhost", "http://metadata.google.internal", "http://foo.local",
    "file:///etc/passwd", "ftp://example.com", "https://user:pass@example.com",
    "https://example.com:8443", "https://example.com:80", "https://example.com\\@127.0.0.1",
    "https://example.com\n", "https://[bad", "http://a..com", "https://%31%32%37.0.0.1",
    None, {}, 7, "", "x" * 2049,
])
def test_unsafe_urls(url):
    with pytest.raises(UnsafeTarget):
        normalize_url(url)


def test_normalization_and_scope():
    assert normalize_url("HTTPS://EXAMPLE.COM:443/search?q=sql#fragment") == "https://example.com/search?q=sql"
    assert normalize_url("https://bücher.de") == "https://xn--bcher-kva.de/"
    assert normalize_url("https://8.8.8.8") == "https://8.8.8.8/"
    assert in_scope("http://example.com/", "https://example.com/page")
    assert not in_scope("https://example.com/", "http://example.com/page")
    assert not in_scope("https://example.com/", "https://example.com.evil.com/page")
    assert not in_scope("https://example.com/", "https://www.example.com/page")
    assert normalize_url("https://example.com?q=1") != normalize_url("https://example.com?q=2")


def test_url_redaction():
    output = redact_url("https://example.com/search?token=VERY_SECRET&q=a&q=b#fragment")
    assert "VERY_SECRET" not in output and "fragment" not in output
    assert output.count("q=") == 2


def test_resolver_rejects_mixed_public_private_answers():
    async def run():
        resolver = PublicResolver()
        resolver._resolver.resolve = AsyncMock(return_value=[{"host": "8.8.8.8"}, {"host": "127.0.0.1"}])
        try:
            with pytest.raises(UnsafeTarget):
                await resolver.resolve("example.com", 443)
        finally:
            await resolver.close()
    asyncio.run(run())


def test_resolver_passes_exact_checked_answers():
    async def run():
        resolver = PublicResolver()
        answers = [{"host": "8.8.8.8"}, {"host": "2606:4700:4700::1111"}]
        resolver._resolver.resolve = AsyncMock(return_value=answers)
        try:
            assert await resolver.resolve("example.com", 443) is answers
        finally:
            await resolver.close()
    asyncio.run(run())
