import time
import threading
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException, status


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter per client IP address.
    Tracks timestamps of requests within a sliding window.
    """
    def __init__(self):
        self._lock = threading.Lock()
        # Storage format: { (client_ip, endpoint_key): [timestamp, timestamp, ...] }
        self._requests: Dict[Tuple[str, str], List[float]] = {}
        self._last_cleanup = time.time()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int, int]:
        """
        Checks if a request is allowed under the rate limit.
        Returns: (allowed: bool, remaining_requests: int, retry_after_seconds: int)
        """
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            # Periodic cleanup of expired entries every 60 seconds
            if now - self._last_cleanup > 60:
                self._cleanup(now)

            if key not in self._requests:
                self._requests[key] = []

            # Filter out timestamps older than the sliding window
            self._requests[key] = [ts for ts in self._requests[key] if ts > window_start]

            current_count = len(self._requests[key])

            if current_count < max_requests:
                self._requests[key].append(now)
                remaining = max_requests - (current_count + 1)
                return True, remaining, 0
            else:
                # Rate limit exceeded.
                # Earliest request within window dictates retry time
                oldest_in_window = self._requests[key][0]
                retry_after = max(1, int(oldest_in_window + window_seconds - now) + 1)
                return False, 0, retry_after

    def _cleanup(self, now: float):
        """Removes keys that have had no requests for over 10 minutes."""
        stale_keys = []
        for k, timestamps in self._requests.items():
            if not timestamps or timestamps[-1] < now - 600:
                stale_keys.append(k)
        for k in stale_keys:
            del self._requests[k]
        self._last_cleanup = now

    def reset(self):
        """Resets all rate limiting state (useful for tests)."""
        with self._lock:
            self._requests.clear()
            self._last_cleanup = time.time()


# Global rate limiter instance
limiter = SlidingWindowRateLimiter()


def get_client_ip(request: Request) -> str:
    """Extracts client IP, respecting X-Forwarded-For if behind a proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def apply_rate_limit(request: Request, endpoint_tag: str, max_requests: int, window_seconds: int):
    """
    Evaluates rate limit and raises HTTP 429 if threshold is breached.
    Attaches X-RateLimit headers to response if called within a route handler.
    """
    client_ip = get_client_ip(request)
    key = f"{client_ip}:{endpoint_tag}"
    allowed, remaining, retry_after = limiter.is_allowed(key, max_requests, window_seconds)

    if not allowed:
        headers = {
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": str(max_requests),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(retry_after),
        }
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers=headers
        )

    # Store rate limit info on request state so middleware/endpoint can attach headers
    request.state.rate_limit_headers = {
        "X-RateLimit-Limit": str(max_requests),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(window_seconds),
    }
    return True
