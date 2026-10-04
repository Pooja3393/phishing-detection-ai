"""URL parsing and public-address checks used before any outbound request."""

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse, urlunparse


class UnsafeURLError(ValueError):
    pass


def normalize_url(value):
    value = str(value or "").strip()
    if not value:
        raise UnsafeURLError("Enter a website URL.")
    if len(value) > 4096:
        raise UnsafeURLError("The URL is too long to analyze.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeURLError("Only HTTP and HTTPS website URLs can be analyzed.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeURLError("Enter a valid URL without embedded login credentials.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise UnsafeURLError("The URL contains an invalid port.") from exc
    host = parsed.hostname.rstrip(".").lower()
    if not host or any(ch.isspace() for ch in host):
        raise UnsafeURLError("Enter a valid website hostname.")
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise UnsafeURLError("Enter a valid website hostname.") from exc
        labels = ascii_host.split(".")
        if len(labels) < 2 or any(
            not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise UnsafeURLError("Enter a fully qualified website domain or IP address.")
    return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def ensure_public_host(url):
    """Reject localhost, private, reserved, and unresolvable destinations."""
    parsed = urlparse(normalize_url(url))
    hostname = parsed.hostname
    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            }
        except OSError as exc:
            raise UnsafeURLError("The website hostname could not be resolved.") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise UnsafeURLError("For safety, private, local, and reserved network addresses cannot be scanned.")


def safe_get(session, url, *, timeout=6, headers=None, max_redirects=5, stream=False):
    """Perform a bounded request, rechecking every redirect destination."""
    current = normalize_url(url)
    response = None
    history = []
    for _ in range(max_redirects + 1):
        ensure_public_host(current)
        response = session.get(
            current,
            timeout=timeout,
            allow_redirects=False,
            headers=headers,
            stream=stream,
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            response.url = current
            response.history = history
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            response.history = history
            return response
        history.append(response)
        current = normalize_url(urljoin(current, location))
    raise UnsafeURLError("The website redirected too many times.")
