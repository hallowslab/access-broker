import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    # General request rate limits (per IP)
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    
    # Specific endpoint limits (per IP)
    register_per_minute: int = 5
    challenge_per_minute: int = 10
    verify_per_minute: int = 10
    
    # Failed verification throttle (progressive backoff)
    failed_verify_threshold: int = 3  # After N failures, apply backoff
    failed_verify_backoff_seconds: int = 60  # Wait N seconds after threshold
    failed_verify_max_backoff: int = 3600  # Max backoff (1 hour)


@dataclass
class RateLimitEntry:
    """Track rate limit state for a key."""
    timestamps: list[float] = field(default_factory=list)
    failed_count: int = 0
    last_failure: float = 0
    backoff_until: float = 0
    
    def cleanup(self, window_seconds: int = 3600):
        """Remove timestamps older than window."""
        cutoff = time.time() - window_seconds
        self.timestamps = [t for t in self.timestamps if t > cutoff]


class RateLimiter:
    """In-memory rate limiter with progressive backoff for failures."""
    
    def __init__(self, config: RateLimitConfig | None = None):
        self.config = config or RateLimitConfig()
        self._entries: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
    
    def _get_entry(self, key: str) -> RateLimitEntry:
        return self._entries[key]
    
    def check_rate_limit(self, key: str, limit_per_minute: int) -> bool:
        """Check if key is within rate limit. Returns True if allowed."""
        entry = self._get_entry(key)
        entry.cleanup(60)
        
        if len(entry.timestamps) >= limit_per_minute:
            return False
        
        entry.timestamps.append(time.time())
        return True
    
    def check_backoff(self, key: str) -> int:
        """Check if key is in backoff period. Returns seconds remaining, 0 if not in backoff."""
        entry = self._get_entry(key)
        if entry.backoff_until > time.time():
            return int(entry.backoff_until - time.time())
        return 0
    
    def record_failure(self, key: str):
        """Record a failed verification attempt and apply backoff if threshold reached."""
        entry = self._get_entry(key)
        entry.failed_count += 1
        entry.last_failure = time.time()
        
        # Apply progressive backoff
        if entry.failed_count >= self.config.failed_verify_threshold:
            backoff = min(
                self.config.failed_verify_backoff_seconds * (entry.failed_count // self.config.failed_verify_threshold),
                self.config.failed_verify_max_backoff
            )
            entry.backoff_until = time.time() + backoff
    
    def record_success(self, key: str):
        """Record a successful verification, resetting failure count."""
        entry = self._get_entry(key)
        entry.failed_count = 0
        entry.backoff_until = 0
    
    def check_register(self, ip: str) -> tuple[bool, str | None]:
        """Check if register request is allowed. Returns (allowed, error_message)."""
        if not self.check_rate_limit(f"register:{ip}", self.config.register_per_minute):
            return False, "rate limit exceeded: too many registration attempts"
        return True, None
    
    def check_challenge(self, ip: str) -> tuple[bool, str | None]:
        """Check if challenge request is allowed."""
        if not self.check_rate_limit(f"challenge:{ip}", self.config.challenge_per_minute):
            return False, "rate limit exceeded: too many challenge requests"
        return True, None
    
    def check_verify(self, ip: str, public_key: str) -> tuple[bool, str | None]:
        """Check if verify request is allowed, with backoff for failures."""
        # Check general rate limit
        if not self.check_rate_limit(f"verify:{ip}", self.config.verify_per_minute):
            return False, "rate limit exceeded: too many verification attempts"
        
        # Check backoff for this IP/key combination
        backoff_key = f"verify_backoff:{ip}:{public_key}"
        remaining = self.check_backoff(backoff_key)
        if remaining > 0:
            return False, f"too many failed verifications, try again in {remaining} seconds"
        
        return True, None
    
    def record_verify_failure(self, ip: str, public_key: str):
        """Record a failed verification attempt."""
        backoff_key = f"verify_backoff:{ip}:{public_key}"
        self.record_failure(backoff_key)
    
    def record_verify_success(self, ip: str, public_key: str):
        """Record a successful verification."""
        backoff_key = f"verify_backoff:{ip}:{public_key}"
        self.record_success(backoff_key)
