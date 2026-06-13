import threading
import time

RATE_LIMIT_WINDOW = 60  # 1 minute in seconds
RATE_LIMIT_MAX = 20  # max attempts per window per key
# Probabilistic cleanup: purge all expired entries roughly 1-in-N calls.
_CLEANUP_PROBABILITY = 50


class RateLimiter:
    def __init__(self, window: int = RATE_LIMIT_WINDOW, max_hits: int = RATE_LIMIT_MAX):
        self.window = window
        self.max_hits = max_hits
        self._hits: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()
        self._call_count = 0

    def check(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            # Periodically purge stale entries to prevent unbounded growth.
            self._call_count += 1
            if self._call_count % _CLEANUP_PROBABILITY == 0:
                expired = [k for k, v in self._hits.items() if now - v[0] > self.window]
                for k in expired:
                    del self._hits[k]

            entry = self._hits.get(key)
            if entry is None or now - entry[0] > self.window:
                self._hits[key] = (now, 1)
                return True
            start, count = entry
            count += 1
            self._hits[key] = (start, count)
            return count <= self.max_hits


_challenge_limiter = RateLimiter()
# Stricter limit for the agent-key payment verification path.
_agent_key_limiter = RateLimiter(max_hits=10)
