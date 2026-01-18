# engine/scheduler/resources.py

from __future__ import annotations
from threading import Lock


class ResourceBudget:
    """
    Deterministic resource budget based on abstract tokens.

    Scheduler-owned.
    Thread-safe.
    """

    def __init__(self, max_tokens: int):
        if max_tokens <= 0:
            raise ValueError("max_tokens must be > 0")

        self._max_tokens = max_tokens
        self._used_tokens = 0
        self._lock = Lock()

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    @property
    def used_tokens(self) -> int:
        return self._used_tokens

    @property
    def available_tokens(self) -> int:
        return self._max_tokens - self._used_tokens

    def can_acquire(self, tokens: int) -> bool:
        if tokens <= 0:
            return False
        return self.available_tokens >= tokens

    def acquire(self, tokens: int) -> bool:
        """
        Attempt to acquire tokens.
        Returns True if successful.
        """
        if tokens <= 0:
            return False

        with self._lock:
            if self._used_tokens + tokens > self._max_tokens:
                return False
            self._used_tokens += tokens
            return True

    def release(self, tokens: int) -> None:
        """
        Release previously acquired tokens.
        """
        if tokens <= 0:
            return

        with self._lock:
            self._used_tokens = max(0, self._used_tokens - tokens)
 
    #test
    def test_resource_budget():
        rb = ResourceBudget(4)
        rb.allocate(3)
        assert rb.available == 1
        rb.release(3)
        assert rb.available == 4

