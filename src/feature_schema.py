"""Shared schema for the legacy UCI-style phishing URL feature dataset."""

FEATURE_NAMES = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail",
    "AbnormalURL", "WebsiteForwarding", "StatusBarCust",
    "DisableRightClick", "UsingPopupWindow", "IframeRedirection",
    "AgeofDomain", "DNSRecording", "WebsiteTraffic", "PageRank",
    "GoogleIndex", "LinksPointingToPage", "StatsReport",
]

TARGET_CANDIDATES = ("class", "label", "target", "is_phishing", "phishing")


def canonical_column(name):
    """Match dataset headers despite harmless whitespace/case differences."""
    return str(name).strip().casefold()
