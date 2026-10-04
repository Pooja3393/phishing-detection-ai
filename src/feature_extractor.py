from html.parser import HTMLParser
from ipaddress import ip_address
from urllib.parse import urljoin, urlparse
import re

import requests
from url_safety import normalize_url, safe_get

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "shorturl.at"
}


class PageSignals(HTMLParser):
    """Collect lightweight page signals used by the original dataset."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resource_urls = []
        self.anchor_urls = []
        self.script_urls = []
        self.form_actions = []
        self.has_favicon = False
        self.has_email = False
        self.has_status_script = False
        self.disables_right_click = False
        self.popup_count = 0
        self.iframe_count = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        tag = tag.lower()

        if tag in {"img", "script", "link", "audio", "video", "source"}:
            resource = attributes.get("src") or attributes.get("href")
            if resource:
                self.resource_urls.append(resource)
                if tag == "script":
                    self.script_urls.append(resource)

        if tag == "a" and attributes.get("href"):
            self.anchor_urls.append(attributes["href"])

        if tag == "link" and "icon" in attributes.get("rel", "").lower():
            self.has_favicon = True

        if tag == "form" and attributes.get("action"):
            self.form_actions.append(attributes["action"])

        if tag == "iframe" or tag == "frame":
            self.iframe_count += 1

        values = " ".join(str(value) for value in attributes.values())
        if "onmouseover" in attributes or "window.status" in values.lower():
            self.has_status_script = True
        if "contextmenu" in values.lower() or "rightclick" in values.lower():
            self.disables_right_click = True
        self.popup_count += len(re.findall(r"\b(?:window\.open|alert)\s*\(", values, re.I))

    def handle_data(self, data):
        if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", data):
            self.has_email = True


def _is_ip(hostname):
    try:
        ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _same_domain(first_url, second_url):
    first = (urlparse(first_url).hostname or "").lower()
    second = (urlparse(second_url).hostname or "").lower()
    return bool(first and second and (first == second or second.endswith("." + first)))


def _value(is_risky):
    return -1 if is_risky else 1


def extract_features(url):
    """Extract the 30 features expected by the trained phishing model."""
    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    signals = PageSignals()
    response = None

    try:
        response = safe_get(
            requests,
            normalized_url,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0 phishing-detector/1.0"},
            stream=True,
        )
        page_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=16_384):
            page_bytes.extend(chunk)
            if len(page_bytes) >= 1_000_000:
                break
        signals.feed(page_bytes.decode(response.encoding or "utf-8", errors="replace"))
        response.close()
    except (requests.RequestException, ValueError):
        pass
    finally:
        if response is not None:
            response.close()

    final_url = response.url if response is not None else normalized_url
    final_parsed = urlparse(final_url)
    final_host = final_parsed.hostname or hostname
    resource_count = len(signals.resource_urls)
    external_resources = sum(
        not _same_domain(final_url, urljoin(final_url, resource))
        for resource in signals.resource_urls
    )
    external_anchors = sum(
        not _same_domain(final_url, urljoin(final_url, anchor))
        for anchor in signals.anchor_urls
    )

    features = [
        _value(_is_ip(hostname)),
        -1 if len(normalized_url) > 75 else (0 if len(normalized_url) >= 54 else 1),
        _value(hostname.lower() in SHORTENERS),
        _value("@" in normalized_url),
        _value(normalized_url.rfind("//") > 7),
        _value("-" in hostname),
        1 if hostname.count(".") <= 1 else (0 if hostname.count(".") == 2 else -1),
        1 if parsed.scheme.lower() == "https" else -1,
        0,  # Domain registration length requires WHOIS data.
        0 if response is None else (1 if signals.has_favicon else -1),
        _value(parsed.port not in (None, 80, 443)),
        _value("https" in hostname.lower()),
        _value(resource_count and external_resources / resource_count > 0.5),
        _value(signals.anchor_urls and external_anchors / len(signals.anchor_urls) > 0.5),
        _value(resource_count and len(signals.script_urls) / resource_count > 0.5),
        _value(any(
            not _same_domain(final_url, urljoin(final_url, action))
            for action in signals.form_actions
        )),
        _value(signals.has_email),
        0 if response is None else _value(final_host != hostname),
        0 if response is None else _value(len(response.history) > 1),
        _value(signals.has_status_script),
        _value(signals.disables_right_click),
        _value(signals.popup_count > 0),
        _value(signals.iframe_count > 0),
        0,  # Domain age requires WHOIS data.
        1 if hostname else -1,
        0,  # Traffic ranking is not available from a URL alone.
        0,  # PageRank is not available from a URL alone.
        1 if response is not None else 0,
        0,  # Inbound-link count is not available from a URL alone.
        0,  # Reputation/statistics report is not available from a URL alone.
    ]

    return features
