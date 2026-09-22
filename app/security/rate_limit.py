"""In-memory rate limiter used for login endpoints and other sensitive routes.

Stores attempts per client key/IP in process memory, which is acceptable for
a single-instance self-hosted deployment. A distributed deployment should
replace this with a Redis-backed limiter (documented in DECOMPLYMENT notes).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)


class RateLimiter:
    def __init__(self, max_hits: int, window_seconds: int) -> None:
        self.max_hits = max_hits
        self.window_seconds = window_seconds

    def allow(self, key: str) -> bool:
        """Return True if the request is within limits, otherwise False."""
        now = time.monotonic()
        with lock:
            q = _hits[key]
            while q and now - q[0] > self.window_seconds:
                q.popleft()
            if len(q) >= self.max_hits:
                return False
            q.append(now)
            return True

    def reset(self, key: str) -> None:
        with lock:
            _hits.pop(key, None)


# Instance for login brute-force protection (per IP + per username).
login_limiter = RateLimiter(max_hits=16, window_seconds=300)
