"""
HappyWallet Rate-Limit Service Tests.

Tests the security-domain rate-limit policy without Django models,
HTTP requests, sessions, persistence, or external services.
"""

from __future__ import annotations

import math

from django.test import SimpleTestCase

from apps.security.rate_limit import (
    AuthenticationRateLimitedError,
    InvalidRateLimitStateError,
    RateLimitResult,
    RateLimitService,
    RateLimitState,
    RateLimitSecurityError,
)


# ============================================================================
# EXCEPTION TESTS
# ============================================================================


class RateLimitExceptionTests(SimpleTestCase):
    """Verify the public exception hierarchy."""

    def test_base_exception_is_exception(self) -> None:
        self.assertTrue(
            issubclass(
                RateLimitSecurityError,
                Exception,
            )
        )

    def test_invalid_state_error_inherits_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                InvalidRateLimitStateError,
                RateLimitSecurityError,
            )
        )

    def test_rate_limited_error_inherits_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                AuthenticationRateLimitedError,
                RateLimitSecurityError,
            )
        )


# ============================================================================
# STATE TESTS
# ============================================================================


class RateLimitStateTests(SimpleTestCase):
    """Verify immutable and validated rate-limit state."""

    def test_default_state_is_clean(self) -> None:
        state = RateLimitState()

        self.assertEqual(state.failures, 0)
        self.assertIsNone(state.locked_until)

    def test_state_accepts_failure_count(self) -> None:
        state = RateLimitState(
            failures=3,
        )

        self.assertEqual(state.failures, 3)

    def test_state_accepts_lockout_timestamp(self) -> None:
        state = RateLimitState(
            failures=5,
            locked_until=130.0,
        )

        self.assertEqual(state.failures, 5)
        self.assertEqual(state.locked_until, 130.0)

    def test_state_is_immutable(self) -> None:
        state = RateLimitState()

        with self.assertRaises(AttributeError):
            state.failures = 1  # type: ignore[misc]


# ============================================================================
# RESULT TESTS
# ============================================================================


class RateLimitResultTests(SimpleTestCase):
    """Verify rate-limit decision objects."""

    def test_allowed_result(self) -> None:
        result = RateLimitResult(
            allowed=True,
            failures=0,
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.failures, 0)
        self.assertIsNone(result.retry_after)

    def test_blocked_result(self) -> None:
        result = RateLimitResult(
            allowed=False,
            failures=5,
            retry_after=30.0,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.failures, 5)
        self.assertEqual(result.retry_after, 30.0)

    def test_result_is_immutable(self) -> None:
        result = RateLimitResult(
            allowed=True,
            failures=0,
        )

        with self.assertRaises(AttributeError):
            result.allowed = False  # type: ignore[misc]


# ============================================================================
# POLICY TESTS
# ============================================================================


class RateLimitPolicyTests(SimpleTestCase):
    """Verify deterministic lockout policy."""

    def test_policy_constants_are_valid(self) -> None:
        self.assertGreater(
            RateLimitService.MAX_FAILURES,
            0,
        )

        self.assertGreater(
            RateLimitService.BASE_LOCKOUT_SECONDS,
            0,
        )

        self.assertGreaterEqual(
            RateLimitService.MAX_LOCKOUT_SECONDS,
            RateLimitService.BASE_LOCKOUT_SECONDS,
        )

    def test_no_lockout_before_threshold(self) -> None:
        for failures in range(
            RateLimitService.MAX_FAILURES
        ):
            self.assertEqual(
                RateLimitService.lockout_seconds(
                    failures
                ),
                0.0,
            )

    def test_lockout_starts_at_threshold(self) -> None:
        result = RateLimitService.lockout_seconds(
            RateLimitService.MAX_FAILURES
        )

        self.assertEqual(
            result,
            RateLimitService.BASE_LOCKOUT_SECONDS,
        )

    def test_lockout_doubles_exponentially(self) -> None:
        base = RateLimitService.BASE_LOCKOUT_SECONDS

        for exponent in range(3):
            failures = (
                RateLimitService.MAX_FAILURES
                + exponent
            )

            expected = min(
                base * (2**exponent),
                RateLimitService.MAX_LOCKOUT_SECONDS,
            )

            self.assertEqual(
                RateLimitService.lockout_seconds(
                    failures
                ),
                expected,
            )

    def test_lockout_is_capped(self) -> None:
        result = RateLimitService.lockout_seconds(
            10_000
        )

        self.assertEqual(
            result,
            RateLimitService.MAX_LOCKOUT_SECONDS,
        )

    def test_lockout_is_capped_for_extremely_large_failure_count(
        self,
    ) -> None:
        result = RateLimitService.lockout_seconds(
            10**100
        )

        self.assertEqual(
            result,
            RateLimitService.MAX_LOCKOUT_SECONDS,
        )

    def test_lockout_result_is_finite(self) -> None:
        result = RateLimitService.lockout_seconds(
            RateLimitService.MAX_FAILURES + 100
        )

        self.assertTrue(
            math.isfinite(result)
        )

    def test_negative_failure_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RateLimitService.lockout_seconds(-1)

    def test_boolean_failure_count_rejected(self) -> None:
        with self.assertRaises(TypeError):
            RateLimitService.lockout_seconds(True)

    def test_non_integer_failure_count_rejected(self) -> None:
        with self.assertRaises(TypeError):
            RateLimitService.lockout_seconds(5.0)  # type: ignore[arg-type]

        with self.assertRaises(TypeError):
            RateLimitService.lockout_seconds("5")  # type: ignore[arg-type]


# ============================================================================
# VALIDATION TESTS
# ============================================================================


class RateLimitValidationTests(SimpleTestCase):
    """Verify state validation."""

    def test_valid_state_is_accepted(self) -> None:
        state = RateLimitState()

        result = RateLimitService.validate_state(
            state
        )

        self.assertIsNone(result)

    def test_invalid_state_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidRateLimitStateError
        ):
            RateLimitService.validate_state(
                object()  # type: ignore[arg-type]
            )

    def test_none_state_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidRateLimitStateError
        ):
            RateLimitService.validate_state(
                None  # type: ignore[arg-type]
            )


# ============================================================================
# STATUS TESTS
# ============================================================================


class RateLimitStatusTests(SimpleTestCase):
    """Verify authentication status decisions."""

    def test_clean_state_is_allowed(self) -> None:
        state = RateLimitState()

        result = RateLimitService.status(
            state,
            now=100.0,
        )

        self.assertIsInstance(
            result,
            RateLimitResult,
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.failures, 0)
        self.assertIsNone(result.retry_after)

    def test_failed_but_unlocked_state_is_allowed(self) -> None:
        state = RateLimitState(
            failures=3,
        )

        result = RateLimitService.status(
            state,
            now=100.0,
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.failures, 3)
        self.assertIsNone(result.retry_after)

    def test_active_lockout_blocks_access(self) -> None:
        state = RateLimitState(
            failures=5,
            locked_until=130.0,
        )

        result = RateLimitService.status(
            state,
            now=100.0,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.failures, 5)
        self.assertEqual(
            result.retry_after,
            30.0,
        )

    def test_expired_lockout_allows_access(self) -> None:
        state = RateLimitState(
            failures=5,
            locked_until=100.0,
        )

        result = RateLimitService.status(
            state,
            now=100.0,
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.failures, 5)
        self.assertIsNone(result.retry_after)

    def test_time_must_be_numeric(self) -> None:
        state = RateLimitState()

        with self.assertRaises(TypeError):
            RateLimitService.status(
                state,
                now="100",  # type: ignore[arg-type]
            )

    def test_boolean_time_is_rejected(self) -> None:
        state = RateLimitState()

        with self.assertRaises(TypeError):
            RateLimitService.status(
                state,
                now=True,  # type: ignore[arg-type]
            )


# ============================================================================
# CHECK TESTS
# ============================================================================


class RateLimitCheckTests(SimpleTestCase):
    """Verify the blocking guard."""

    def test_check_allows_unlocked_state(self) -> None:
        state = RateLimitState(
            failures=2,
        )

        result = RateLimitService.check(
            state,
            now=100.0,
        )

        self.assertIsNone(result)

    def test_check_raises_when_locked(self) -> None:
        state = RateLimitState(
            failures=5,
            locked_until=130.0,
        )

        with self.assertRaises(
            AuthenticationRateLimitedError
        ):
            RateLimitService.check(
                state,
                now=100.0,
            )

    def test_check_allows_expired_lockout(self) -> None:
        state = RateLimitState(
            failures=5,
            locked_until=100.0,
        )

        result = RateLimitService.check(
            state,
            now=100.0,
        )

        self.assertIsNone(result)


# ============================================================================
# FAILURE TESTS
# ============================================================================


class RateLimitFailureTests(SimpleTestCase):
    """Verify failure-state transitions."""

    def test_first_failure_increments_counter(self) -> None:
        state = RateLimitState()

        updated = RateLimitService.record_failure(
            state,
            now=100.0,
        )

        self.assertEqual(
            updated.failures,
            1,
        )

        self.assertIsNone(
            updated.locked_until
        )

    def test_failures_increment_until_threshold(self) -> None:
        state = RateLimitState()

        for expected_failures in range(
            1,
            RateLimitService.MAX_FAILURES,
        ):
            state = RateLimitService.record_failure(
                state,
                now=100.0,
            )

            self.assertEqual(
                state.failures,
                expected_failures,
            )

            self.assertIsNone(
                state.locked_until
            )

    def test_threshold_failure_starts_lockout(self) -> None:
        state = RateLimitState()

        for _ in range(
            RateLimitService.MAX_FAILURES
        ):
            state = RateLimitService.record_failure(
                state,
                now=100.0,
            )

        self.assertEqual(
            state.failures,
            RateLimitService.MAX_FAILURES,
        )

        self.assertEqual(
            state.locked_until,
            100.0
            + RateLimitService.BASE_LOCKOUT_SECONDS,
        )

    def test_second_lockout_doubles_duration(self) -> None:
        state = RateLimitState()

        for _ in range(
            RateLimitService.MAX_FAILURES
        ):
            state = RateLimitService.record_failure(
                state,
                now=100.0,
            )

        self.assertIsNotNone(
            state.locked_until
        )

        # Lockout must expire before another failure
        # can be recorded.
        state = RateLimitService.record_failure(
            state,
            now=100.0
            + RateLimitService.BASE_LOCKOUT_SECONDS,
        )

        expected = min(
            RateLimitService.BASE_LOCKOUT_SECONDS * 2,
            RateLimitService.MAX_LOCKOUT_SECONDS,
        )

        self.assertEqual(
            state.locked_until,
            100.0
            + RateLimitService.BASE_LOCKOUT_SECONDS
            + expected,
        )

    def test_failure_during_lockout_is_rejected(self) -> None:
        state = RateLimitState(
            failures=RateLimitService.MAX_FAILURES,
            locked_until=200.0,
        )

        with self.assertRaises(
            AuthenticationRateLimitedError
        ):
            RateLimitService.record_failure(
                state,
                now=199.0,
            )

    def test_failure_after_lockout_expiry_is_allowed(self) -> None:
        state = RateLimitState(
            failures=RateLimitService.MAX_FAILURES,
            locked_until=200.0,
        )

        updated = RateLimitService.record_failure(
            state,
            now=200.0,
        )

        self.assertEqual(
            updated.failures,
            RateLimitService.MAX_FAILURES + 1,
        )

    def test_record_failure_does_not_mutate_original_state(
        self,
    ) -> None:
        state = RateLimitState()

        updated = RateLimitService.record_failure(
            state,
            now=100.0,
        )

        self.assertIsNot(
            state,
            updated,
        )

        self.assertEqual(
            state.failures,
            0,
        )

        self.assertEqual(
            updated.failures,
            1,
        )

    def test_lockout_is_capped_after_many_failures(
        self,
    ) -> None:
        state = RateLimitState(
            failures=10_000,
        )

        # The state is intentionally supplied with an expired/no
        # lockout so the service can process the next failure.
        state = RateLimitState(
            failures=10_000,
            locked_until=None,
        )

        updated = RateLimitService.record_failure(
            state,
            now=100.0,
        )

        self.assertEqual(
            updated.locked_until,
            100.0
            + RateLimitService.MAX_LOCKOUT_SECONDS,
        )


# ============================================================================
# SUCCESS TESTS
# ============================================================================


class RateLimitSuccessTests(SimpleTestCase):
    """Verify successful authentication reset."""

    def test_success_resets_failures(self) -> None:
        state = RateLimitState(
            failures=5,
            locked_until=200.0,
        )

        updated = RateLimitService.record_success(
            state
        )

        self.assertEqual(
            updated.failures,
            0,
        )

        self.assertIsNone(
            updated.locked_until
        )

    def test_success_returns_fresh_state(self) -> None:
        state = RateLimitState(
            failures=3,
        )

        updated = RateLimitService.record_success(
            state
        )

        self.assertIsNot(
            state,
            updated,
        )

    def test_success_does_not_mutate_original(self) -> None:
        state = RateLimitState(
            failures=3,
            locked_until=150.0,
        )

        RateLimitService.record_success(
            state
        )

        self.assertEqual(
            state.failures,
            3,
        )

        self.assertEqual(
            state.locked_until,
            150.0,
        )


# ============================================================================
# EXTREME INPUT TESTS
# ============================================================================


class RateLimitExtremeInputTests(SimpleTestCase):
    """
    Verify that hostile/extreme counters cannot trigger
    unbounded exponentiation.
    """

    def test_huge_failure_count_does_not_overflow(self) -> None:
        result = RateLimitService.lockout_seconds(
            10**10_000
        )

        self.assertEqual(
            result,
            RateLimitService.MAX_LOCKOUT_SECONDS,
        )

    def test_huge_failure_count_is_finite(self) -> None:
        result = RateLimitService.lockout_seconds(
            10**1000
        )

        self.assertTrue(
            math.isfinite(result)
        )

    def test_record_failure_with_huge_counter_is_capped(
        self,
    ) -> None:
        state = RateLimitState(
            failures=10**10_000,
            locked_until=None,
        )

        updated = RateLimitService.record_failure(
            state,
            now=100.0,
        )

        self.assertEqual(
            updated.locked_until,
            100.0
            + RateLimitService.MAX_LOCKOUT_SECONDS,
        )


# ============================================================================
# PUBLIC API TESTS
# ============================================================================


class RateLimitPublicAPITests(SimpleTestCase):
    """Verify the public module surface."""

    def test_service_is_available(self) -> None:
        self.assertTrue(
            hasattr(
                RateLimitService,
                "status",
            )
        )

    def test_required_methods_are_available(self) -> None:
        required_methods = (
            "validate_state",
            "status",
            "check",
            "record_failure",
            "record_success",
            "lockout_seconds",
        )

        for method_name in required_methods:
            self.assertTrue(
                hasattr(
                    RateLimitService,
                    method_name,
                ),
                method_name,
            )