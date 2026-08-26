import re as _re

def is_public_path(pathname: str) -> bool:
    return pathname == "/robots.txt" or pathname.startswith("/.well-known/")


# Sec-Fetch-* headers were introduced in Chrome 76 (2019) and Firefox 90 (2021).
# Older browsers, some mobile WebViews, and certain proxies strip them.
# This UA pattern matches common desktop/mobile browsers as a fallback so they
# get a challenge rather than a 402.
_BROWSER_UA_RE = _re.compile(
    r"(Chrome|Chromium|Firefox|Safari|Edg|OPR|Opera|SamsungBrowser|UCBrowser|Mobile Safari)"
    r"(?!/.*bot)",  # exclude UA strings that contain the browser name followed by /.*bot
    _re.IGNORECASE,
)
# Explicit bot/crawler suffixes that should NOT match even if they spoof a browser UA.
_BOT_UA_RE = _re.compile(r"bot|crawl|spider|slurp|mediapartners|adsbot", _re.IGNORECASE)


def is_browser_from_headers(headers: dict) -> bool:
    # Primary signal: Fetch metadata headers (Chrome 76+, Firefox 90+).
    if headers.get("sec-fetch-mode") or headers.get("sec-fetch-dest"):
        return True
    # Fallback: UA heuristic for older browsers that don't send Sec-Fetch-*.
    ua = headers.get("user-agent") or headers.get("User-Agent") or ""
    if ua and not _BOT_UA_RE.search(ua) and _BROWSER_UA_RE.search(ua):
        return True
    return False
