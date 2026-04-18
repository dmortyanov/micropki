import time
from threading import Lock

class RateLimiter:
    def __init__(self, capacity: int, refill_rate: float):
        """
        Token bucket rate limiter.
        capacity: Maximum burst size (tokens).
        refill_rate: Tokens added per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = Lock()
        
    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

class IPRateLimiter:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.limiters = {}
        self.lock = Lock()
        
    def allow_request(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.limiters:
                self.limiters[ip] = RateLimiter(self.capacity, self.refill_rate)
            limiter = self.limiters[ip]
        return limiter.consume(1)
