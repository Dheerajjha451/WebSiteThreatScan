"""URL and DNS policy applied at the outbound connection boundary."""
import ipaddress
import re
import socket
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp


class UnsafeTarget(ValueError):
    pass


def require_public_ip(value: str) -> None:
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast:
        raise UnsafeTarget("Only public Internet addresses can be scanned.")
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            raise UnsafeTarget("IPv6 transition addresses are not supported.")
        if address in ipaddress.ip_network("64:ff9b::/96") or address in ipaddress.ip_network("64:ff9b:1::/48"):
            raise UnsafeTarget("IPv6 translation addresses are not supported.")


def normalize_url(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise UnsafeTarget("Provide an HTTP or HTTPS URL of at most 2048 characters.")
    if re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise UnsafeTarget("URLs cannot contain whitespace, control characters or backslashes.")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise UnsafeTarget("An absolute HTTP or HTTPS URL is required.")
        if parsed.username is not None or parsed.password is not None:
            raise UnsafeTarget("Credentials in URLs are not allowed.")
        if parsed.port not in {None, 80 if parsed.scheme == "http" else 443}:
            raise UnsafeTarget("Only the standard HTTP and HTTPS ports are allowed.")
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                raise UnsafeTarget("The hostname is invalid.") from None
            if "." not in host or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
                raise UnsafeTarget("Only public Internet hostnames can be scanned.")
        else:
            require_public_ip(str(address))
            host = f"[{address}]" if address.version == 6 else str(address)
        return urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, UnsafeTarget):
            raise
        raise UnsafeTarget("The URL is malformed.") from None


def in_scope(target: str, candidate: str) -> bool:
    root, other = urlsplit(target), urlsplit(candidate)
    return root.hostname == other.hostname and (
        root.scheme == other.scheme or (root.scheme == "http" and other.scheme == "https")
    )


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


class PublicResolver(aiohttp.abc.AbstractResolver):
    """Validate all DNS answers and hand those exact IPs to the connector.

    A separate lookup would leave a DNS rebinding race. Literal IPs bypass
    aiohttp's resolver and are instead checked by normalize_url.
    """
    def __init__(self):
        self._resolver = aiohttp.resolver.ThreadedResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        answers = await self._resolver.resolve(host, port, family)
        if not answers:
            raise UnsafeTarget("The target hostname has no usable DNS records.")
        for answer in answers:
            require_public_ip(answer["host"])
        return answers

    async def close(self):
        await self._resolver.close()
