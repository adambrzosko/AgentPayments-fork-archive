"""
Verified search crawler detection.

UA heuristic + reverse/forward DNS (Google's documented method).
Results are cached for 1 hour to avoid repeated DNS lookups.
"""
import re
import socket
import time
import threading
from typing import Optional

# (ua_pattern, expected_ptr_suffix)
# suffix=None means UA match only — not recommended, included for completeness.
CRAWLERS = [
    (re.compile(r'googlebot', re.I),             '.googlebot.com'),
    (re.compile(r'google-inspectiontool', re.I), '.google.com'),
    (re.compile(r'bingbot', re.I),               '.search.msn.com'),
    (re.compile(r'slurp', re.I),                 '.crawl.yahoo.net'),
    (re.compile(r'duckduckbot', re.I),           '.duckduckgo.com'),
    (re.compile(r'baiduspider', re.I),           '.crawl.baidu.com'),
    (re.compile(r'yandexbot', re.I),             '.yandex.com'),
    (re.compile(r'applebot', re.I),              '.applebot.apple.com'),
]

CRAWLER_CACHE_TTL = 3600  # 1 hour
_cache: dict[str, tuple[bool, float]] = {}  # ip -> (verified, expiry)
_cache_lock = threading.Lock()


def is_verified_crawler(ip: str, user_agent: str) -> bool:
    """
    Return True if the request is from a verified search crawler.

    Verification is: UA matches a known crawler pattern AND the IP's reverse-DNS
    hostname ends with the crawler's published suffix AND a forward DNS lookup of
    that hostname resolves back to the same IP.

    Results are cached for 1 hour to limit DNS round-trips. Blocking I/O — for
    FastAPI/async use, call this in a thread-pool executor.
    """
    if not user_agent or not ip or ip == 'unknown':
        return False

    match = next((c for c in CRAWLERS if c[0].search(user_agent)), None)
    if match is None:
        return False

    suffix = match[1]

    with _cache_lock:
        entry = _cache.get(ip)
        if entry is not None and entry[1] > time.time():
            return entry[0]

    verified = _verify_dns(ip, suffix)

    with _cache_lock:
        _cache[ip] = (verified, time.time() + CRAWLER_CACHE_TTL)

    return verified


def _verify_dns(ip: str, suffix: str) -> bool:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if not hostname.endswith(suffix):
            return False
        # Forward verify: resolve hostname back and confirm it includes the original IP.
        results = socket.getaddrinfo(hostname, None)
        resolved_ips = {r[4][0] for r in results}
        return ip in resolved_ips
    except Exception:
        return False
