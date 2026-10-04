"""Combine independent URL signals without treating HTTPS as a verdict."""

import re
from urllib.parse import urlparse
from url_safety import normalize_url


def calculate_risk(url, prediction, drift, confidence=None):
    score = 0
    reasons = []
    parsed = urlparse(normalize_url(url))
    hostname = (parsed.hostname or "").lower()

    # HTTP is a real transport weakness, but should never decide the verdict alone.
    if parsed.scheme.lower() == "http":
        score += 10
        reasons.append("This site does not use HTTPS; avoid entering sensitive information on an untrusted network.")

    # Account and verification wording is common on legitimate sites too.
    # Treat it as context, not proof of phishing.
    url_text = (parsed.path + "?" + parsed.query).lower()
    path_terms = set(re.findall(r"[a-z0-9]+", url_text))
    account_terms = {"login", "signin", "verify", "verification", "account", "secure", "password", "credential"}
    matched_terms = path_terms & account_terms
    if len(matched_terms) >= 2:
        score += 12
        reasons.append("The URL path combines account or verification terms; check the domain carefully before signing in.")
    elif matched_terms:
        score += 5
        reasons.append("The URL path contains account-related wording; this is common on legitimate sites but merits care.")

    if hostname.endswith((".test", ".invalid", ".example")):
        score += 15
        reasons.append("This uses a reserved test/example domain and cannot be verified as a public website.")
    brand_terms = {"paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix"}
    query_terms = set(re.findall(r"[a-z0-9]+", parsed.query.lower()))
    if (brand_terms & query_terms) and not any(brand in hostname for brand in brand_terms & query_terms):
        score += 8
        reasons.append("A recognizable brand name appears in the URL parameters, not the website's domain; verify the actual domain.")

    

    shorteners = {
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "t.co",
        "buff.ly", "rb.gy", "cutt.ly", "shorturl.at",
    }
    if hostname in shorteners:
        score += 12
        reasons.append("The URL uses a link-shortening service, so its final destination may be hidden.")
    if "@" in parsed.netloc:
        score += 15
        reasons.append("The URL contains an @ sign, which can obscure the actual destination.")

    host_without_brackets = hostname.strip("[]")
    if host_without_brackets and all(part.isdigit() for part in host_without_brackets.split(".")):
        score += 15
        reasons.append("The destination uses a numeric IP address instead of a familiar domain name.")
    if "-" in hostname:
        score += 5
        reasons.append("The domain contains a hyphen; this alone does not establish malicious intent.")

    status = drift.get("status") if isinstance(drift, dict) else None
    if status in {"Connection Timeout", "Connection Failed", "Request Failed"}:
        score += 8
        reasons.append("The destination could not be verified at scan time.")
    elif status == "Not Found":
        score += 5
        reasons.append("The destination returned HTTP 404; broken pages can still belong to legitimate sites.")
    elif status == "Server Error":
        score += 5
        reasons.append("The destination returned a server error during this check.")

    # A phishing label is useful only when the model is reasonably confident.
    if prediction == -1:
        phishing_weight = 20 if confidence is None else round(20 * min(max(confidence, 50), 100) / 100)
        score += phishing_weight
        reasons.append("The URL model flagged phishing indicators; this is a risk signal, not proof.")
    elif prediction == 0:
        score += 8
        reasons.append("The URL model could not make a stable classification from the available evidence.")

    score = min(score, 100)
    risk = "Low" if score < 25 else "Medium" if score < 55 else "High"
    return score, risk, reasons
