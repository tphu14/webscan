"""
rate_limiter.py - Token Bucket rate limiter để tránh bị ban IP / trigger IDS.
"""
import asyncio
import time


class TokenBucketRateLimiter:
    """
    Token Bucket Algorithm:
    - Tokens tích lũy theo thời gian (rate tokens/giây)
    - Mỗi request tiêu thụ 1 token
    - Nếu hết token → đợi đến khi có token mới

    Mặc định: 10 req/s, burst tối đa 20 requests
    """

    def __init__(self, rate: float = 10.0, burst: int = 20):
        self.rate = rate        # tokens per second
        self.burst = burst      # max tokens (burst capacity)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Chờ cho đến khi có token, rồi tiêu thụ 1 token."""
        async with self._lock:
            self._refill()
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._refill()
            self._tokens -= 1.0

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate)
        self._last = now

    @property
    def current_tokens(self) -> float:
        self._refill()
        return round(self._tokens, 2)