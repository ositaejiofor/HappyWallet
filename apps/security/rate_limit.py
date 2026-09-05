"""
HappyWallet Security Rate-Limiting Service.

Security boundary
-----------------

    Authentication / Sensitive Operation
                    |
                    v
             RateLimitService
                    |
          +---------+---------+
          |                   |
      Failure tracking     Lockout policy
          |                   |
          +---------+---------+
                    |
                    v
             Access decision


Responsibilities
----------------

This module owns:

    - authentication failure tracking
    - lockout duration calculation
    - lockout state transitions
    - successful-attempt reset
    - failure thresholds
    - exponential backoff
    - maximum lockout enforcement
    - immutable rate-limit state

This module deliberately does NOT know about:

    - Django models
    - HTTP requests
    - sessions
    - templates
    - database persistence
    - wallets
    - private keys
    - blockchain RPC
    - encryption
    - password hashing


Security properties
-------------------

    - deterministic lockout policy
    - exponential backoff
    - hard maximum lockout
    - no unbounded integer exponentiation
    - invalid counters are rejected
    - bool values are rejected where integers are expected
    - successful authentication clears failures
    - immutable state objects
    - no persistence assumptions
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Final


# ============================================================================
# EXCEPTIONS
# ============================================================================


class RateLimitSecurityError(Exception):
    """Base exception for rate-limit security failures."""


class InvalidRateLimitStateError(RateLimitSecurityError):
    """Raised when rate-limit state is malformed or invalid."""


class AuthenticationRateLimitedError(RateLimitSecurityError):
    """Raised when authentication is temporarily rate limited."""


# ============================================================================
# STATE
# ============================================================================


@dataclass(frozen=True, slots=True)
class RateLimitState:
    """
    Immutable authentication rate-limit state.

    failures:
        Number of consecutive failed authentication attempts.

    locked_until:
        Monotonic-clock timestamp until which authentication
        remains blocked, or ``None`` when not locked.
    """

    failures: int = 0
    locked_until: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.failures, int):
            raise TypeError(
                "Failure count must be an integer."
            )

        if isinstance(self.failures, bool):
            raise TypeError(
                "Failure count must be an integer."
            )

        if self.failures < 0:
            raise ValueError(
                "Failure count cannot be negative."
            )

        if self.locked_until is not None:
            if not isinstance(
                self.locked_until,
                (int, float),
            ):
                raise TypeError(
                    "Lockout timestamp must be numeric or None."
                )

            if isinstance(self.locked_until, bool):
                raise TypeError(
                    "Lockout timestamp must be numeric or None."
                )


# ============================================================================
# RESULT
# ============================================================================


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """
    Immutable result of a rate-limit status check.

    allowed:
        Whether authentication may currently proceed.

    failures:
        Current consecutive failure count.

    retry_after:
        Remaining lockout duration in seconds, or ``None`` when
        authentication is currently allowed.
    """

    allowed: bool
    failures: int
    retry_after: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError(
                "Allowed state must be boolean."
            )

        if not isinstance(self.failures, int):
            raise TypeError(
                "Failure count must be an integer."
            )

        if isinstance(self.failures, bool):
            raise TypeError(
                "Failure count must be an integer."
            )

        if self.failures < 0:
            raise ValueError(
                "Failure count cannot be negative."
            )

        if self.retry_after is not None:
            if not isinstance(
                self.retry_after,
                (int, float),
            ):
                raise TypeError(
                    "Retry delay must be numeric or None."
                )

            if isinstance(self.retry_after, bool):
                raise TypeError(
                    "Retry delay must be numeric or None."
                )

            if self.retry_after < 0:
                raise ValueError(
                    "Retry delay cannot be negative."
                )


# ============================================================================
# RATE-LIMIT SERVICE
# ============================================================================


class RateLimitService:
    """
    Deterministic authentication rate-limit policy.

    This service does not persist state.

    The caller owns persistence and should store only the
    ``RateLimitState`` values necessary for its authentication
    workflow.
    """

    # =========================================================================
    # POLICY
    # =========================================================================

    MAX_FAILURES: Final[int] = 5

    BASE_LOCKOUT_SECONDS: Final[float] = 30.0

    MAX_LOCKOUT_SECONDS: Final[float] = 900.0

    # =========================================================================
    # VALIDATION
    # =========================================================================

    @classmethod
    def validate_state(
        cls,
        state: RateLimitState,
    ) -> None:
        """Validate a rate-limit state object."""

        if not isinstance(state, RateLimitState):
            raise InvalidRateLimitStateError(
                "Rate-limit state must be a RateLimitState."
            )

    # =========================================================================
    # STATUS
    # =========================================================================

    @classmethod
    def status(
        cls,
        state: RateLimitState,
        *,
        now: float,
    ) -> RateLimitResult:
        """
        Determine whether authentication is currently allowed.

        ``now`` must come from a monotonic clock supplied by the
        application layer.
        """
        cls.validate_state(state)

        if not isinstance(now, (int, float)):
            raise TypeError(
                "Current time must be numeric."
            )

        if isinstance(now, bool):
            raise TypeError(
                "Current time must be numeric."
            )

        if (
            state.locked_until is not None
            and now < state.locked_until
        ):
            return RateLimitResult(
                allowed=False,
                failures=state.failures,
                retry_after=state.locked_until - now,
            )

        return RateLimitResult(
            allowed=True,
            failures=state.failures,
        )

    # =========================================================================
    # CHECK
    # =========================================================================

    @classmethod
    def check(
        cls,
        state: RateLimitState,
        *,
        now: float,
    ) -> None:
        """
        Raise AuthenticationRateLimitedError if authentication
        is currently blocked.
        """
        result = cls.status(
            state,
            now=now,
        )

        if not result.allowed:
            raise AuthenticationRateLimitedError(
                "Authentication is temporarily rate limited."
            )

    # =========================================================================
    # FAILURE
    # =========================================================================

    @classmethod
    def record_failure(
        cls,
        state: RateLimitState,
        *,
        now: float,
    ) -> RateLimitState:
        """
        Record one failed authentication attempt.

        Lockout duration increases exponentially after the
        configured failure threshold.
        """
        cls.validate_state(state)

        cls.check(
            state,
            now=now,
        )

        failures = state.failures + 1

        lockout = cls.lockout_seconds(failures)

        if lockout <= 0.0:
            return replace(
                state,
                failures=failures,
                locked_until=None,
            )

        return replace(
            state,
            failures=failures,
            locked_until=now + lockout,
        )

    # =========================================================================
    # SUCCESS
    # =========================================================================

    @classmethod
    def record_success(
        cls,
        state: RateLimitState,
    ) -> RateLimitState:
        """
        Reset authentication failure state after success.
        """
        cls.validate_state(state)

        return RateLimitState()

    # =========================================================================
    # LOCKOUT CALCULATION
    # =========================================================================

    @classmethod
    def lockout_seconds(
        cls,
        failures: int,
    ) -> float:
        """
        Calculate the lockout duration for a failure count.

        Returns zero when the configured failure threshold
        has not been reached.

        The exponential calculation is deliberately capped
        before constructing a potentially enormous integer.
        """
        if not isinstance(failures, int):
            raise TypeError(
                "Failure count must be an integer."
            )

        if isinstance(failures, bool):
            raise TypeError(
                "Failure count must be an integer."
            )

        if failures < 0:
            raise ValueError(
                "Failure count cannot be negative."
            )

        if failures < cls.MAX_FAILURES:
            return 0.0

        exponent = failures - cls.MAX_FAILURES

        if cls.BASE_LOCKOUT_SECONDS >= cls.MAX_LOCKOUT_SECONDS:
            return float(cls.MAX_LOCKOUT_SECONDS)

        max_exponent = 0
        duration = cls.BASE_LOCKOUT_SECONDS

        while duration < cls.MAX_LOCKOUT_SECONDS:
            duration *= 2
            max_exponent += 1

        if exponent >= max_exponent:
            return float(cls.MAX_LOCKOUT_SECONDS)

        return float(
            min(
                cls.BASE_LOCKOUT_SECONDS * (2**exponent),
                cls.MAX_LOCKOUT_SECONDS,
            )
        )


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "AuthenticationRateLimitedError",
    "InvalidRateLimitStateError",
    "RateLimitResult",
    "RateLimitSecurityError",
    "RateLimitService",
    "RateLimitState",
]