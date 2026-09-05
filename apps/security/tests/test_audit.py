"""
HappyWallet Security Audit Service Tests.

Tests cover:

    - audit event construction
    - event validation
    - outcome validation
    - timestamp validation
    - actor/request validation
    - metadata validation
    - sensitive metadata rejection
    - immutable audit events
    - audit sink integration
    - success/failure/denied/warning helpers
    - null sink behavior
    - unsupported metadata types
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

from django.test import SimpleTestCase

from apps.security.audit import (
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditSecurityError,
    AuditService,
    InvalidAuditEventError,
    NullAuditSink,
    UnsafeAuditMetadataError,
    sanitize_metadata,
)


# ============================================================================
# TEST SINK
# ============================================================================


class RecordingAuditSink:
    """In-memory sink used to verify audit persistence behavior."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


# ============================================================================
# EXCEPTIONS
# ============================================================================


class AuditExceptionTests(SimpleTestCase):
    """Verify the audit exception hierarchy."""

    def test_base_exception_is_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                AuditSecurityError,
                Exception,
            )
        )

    def test_invalid_event_error_is_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                InvalidAuditEventError,
                AuditSecurityError,
            )
        )

    def test_unsafe_metadata_error_is_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                UnsafeAuditMetadataError,
                AuditSecurityError,
            )
        )


# ============================================================================
# ENUM TESTS
# ============================================================================


class AuditEventTypeTests(SimpleTestCase):
    """Verify supported audit event types."""

    def test_login_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.LOGIN_SUCCESS.value,
            "login_success",
        )

        self.assertEqual(
            AuditEventType.LOGIN_FAILURE.value,
            "login_failure",
        )

    def test_password_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.PASSWORD_CHANGED.value,
            "password_changed",
        )

        self.assertEqual(
            AuditEventType.PASSWORD_VERIFICATION_FAILED.value,
            "password_verification_failed",
        )

    def test_pin_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.PIN_CHANGED.value,
            "pin_changed",
        )

        self.assertEqual(
            AuditEventType.PIN_VERIFICATION_FAILED.value,
            "pin_verification_failed",
        )

    def test_wallet_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.WALLET_CREATED.value,
            "wallet_created",
        )

        self.assertEqual(
            AuditEventType.WALLET_IMPORTED.value,
            "wallet_imported",
        )

        self.assertEqual(
            AuditEventType.WALLET_LOCKED.value,
            "wallet_locked",
        )

        self.assertEqual(
            AuditEventType.WALLET_UNLOCKED.value,
            "wallet_unlocked",
        )

    def test_vault_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.VAULT_LOCKED.value,
            "vault_locked",
        )

        self.assertEqual(
            AuditEventType.VAULT_UNLOCKED.value,
            "vault_unlocked",
        )

    def test_transaction_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.TRANSACTION_SIGNING_STARTED.value,
            "transaction_signing_started",
        )

        self.assertEqual(
            AuditEventType.TRANSACTION_SIGNING_FAILED.value,
            "transaction_signing_failed",
        )

        self.assertEqual(
            AuditEventType.TRANSACTION_SIGNING_SUCCEEDED.value,
            "transaction_signing_succeeded",
        )

    def test_usb_events_exist(self) -> None:
        self.assertEqual(
            AuditEventType.USB_VAULT_CONNECTED.value,
            "usb_vault_connected",
        )

        self.assertEqual(
            AuditEventType.USB_VAULT_DISCONNECTED.value,
            "usb_vault_disconnected",
        )


class AuditOutcomeTests(SimpleTestCase):
    """Verify audit outcomes."""

    def test_success_value(self) -> None:
        self.assertEqual(
            AuditOutcome.SUCCESS.value,
            "success",
        )

    def test_failure_value(self) -> None:
        self.assertEqual(
            AuditOutcome.FAILURE.value,
            "failure",
        )

    def test_denied_value(self) -> None:
        self.assertEqual(
            AuditOutcome.DENIED.value,
            "denied",
        )

    def test_warning_value(self) -> None:
        self.assertEqual(
            AuditOutcome.WARNING.value,
            "warning",
        )


# ============================================================================
# METADATA TESTS
# ============================================================================


class AuditMetadataTests(SimpleTestCase):
    """Verify metadata security boundaries."""

    def test_none_metadata_becomes_empty_dictionary(self) -> None:
        result = sanitize_metadata(None)

        self.assertEqual(
            result,
            {},
        )

    def test_empty_metadata_is_allowed(self) -> None:
        result = sanitize_metadata({})

        self.assertEqual(
            result,
            {},
        )

    def test_safe_metadata_is_preserved(self) -> None:
        result = sanitize_metadata(
            {
                "ip_address": "127.0.0.1",
                "attempts": 3,
                "success": True,
                "delay": 30.0,
                "reason": None,
            }
        )

        self.assertEqual(
            result["ip_address"],
            "127.0.0.1",
        )

        self.assertEqual(
            result["attempts"],
            3,
        )

        self.assertTrue(
            result["success"]
        )

        self.assertEqual(
            result["delay"],
            30.0,
        )

        self.assertIsNone(
            result["reason"]
        )

    def test_metadata_keys_are_normalized(self) -> None:
        result = sanitize_metadata(
            {
                " IP_ADDRESS ": "127.0.0.1",
            }
        )

        self.assertEqual(
            result,
            {
                "ip_address": "127.0.0.1",
            },
        )

    def test_non_mapping_metadata_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            sanitize_metadata(
                "unsafe"
            )

    def test_non_string_metadata_key_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    123: "value",
                }
            )

    def test_empty_metadata_key_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "   ": "value",
                }
            )

    def test_list_metadata_value_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "items": ["a", "b"],
                }
            )

    def test_dictionary_metadata_value_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "details": {
                        "status": "ok",
                    },
                }
            )


# ============================================================================
# SENSITIVE METADATA TESTS
# ============================================================================


class SensitiveMetadataTests(SimpleTestCase):
    """Verify credential material can never enter audit metadata."""

    def test_password_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "password": "SuperSecretPassword",
                }
            )

    def test_passphrase_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "passphrase": "secret",
                }
            )

    def test_pin_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "pin": "123456",
                }
            )

    def test_otp_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "otp": "123456",
                }
            )

    def test_private_key_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "private_key": "0xdeadbeef",
                }
            )

    def test_seed_phrase_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "seed_phrase": "word " * 12,
                }
            )

    def test_mnemonic_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "mnemonic": "secret words",
                }
            )

    def test_xprv_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "xprv": "xprv-secret",
                }
            )

    def test_api_key_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "api_key": "secret-api-key",
                }
            )

    def test_access_token_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "access_token": "secret-token",
                }
            )

    def test_sensitive_keys_are_case_insensitive(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "PASSWORD": "secret",
                }
            )

    def test_sensitive_keys_are_whitespace_insensitive(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            sanitize_metadata(
                {
                    "  private_key  ": "secret",
                }
            )


# ============================================================================
# EVENT TESTS
# ============================================================================


class AuditEventTests(SimpleTestCase):
    """Verify immutable audit events."""

    def test_event_can_be_created(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        self.assertEqual(
            event.event_type,
            AuditEventType.LOGIN_SUCCESS,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.SUCCESS,
        )

        self.assertEqual(
            event.timestamp,
            100.0,
        )

    def test_event_accepts_actor_id(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
            actor_id="user-123",
        )

        self.assertEqual(
            event.actor_id,
            "user-123",
        )

    def test_event_accepts_request_id(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
            request_id="request-123",
        )

        self.assertEqual(
            event.request_id,
            "request-123",
        )

    def test_event_accepts_metadata(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
            metadata={
                "method": "password",
                "attempt": 1,
            },
        )

        self.assertEqual(
            event.metadata["method"],
            "password",
        )

    def test_event_is_immutable(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        with self.assertRaises(FrozenInstanceError):
            event.timestamp = 200.0  # type: ignore[misc]

    def test_invalid_event_type_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type="login_success",  # type: ignore[arg-type]
                outcome=AuditOutcome.SUCCESS,
                timestamp=100.0,
            )

    def test_invalid_outcome_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome="success",  # type: ignore[arg-type]
                timestamp=100.0,
            )

    def test_boolean_timestamp_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                timestamp=True,
            )

    def test_string_timestamp_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                timestamp="100",  # type: ignore[arg-type]
            )

    def test_negative_timestamp_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                timestamp=-1,
            )

    def test_empty_actor_id_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                timestamp=100.0,
                actor_id="",
            )

    def test_empty_request_id_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                timestamp=100.0,
                request_id="",
            )

    def test_sensitive_metadata_is_rejected(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            AuditEvent(
                event_type=AuditEventType.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                timestamp=100.0,
                metadata={
                    "password": "secret",
                },
            )


# ============================================================================
# NULL SINK TESTS
# ============================================================================


class NullAuditSinkTests(SimpleTestCase):
    """Verify the default no-op sink."""

    def test_null_sink_accepts_valid_event(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGOUT,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        sink = NullAuditSink()

        sink.write(event)

    def test_null_sink_rejects_invalid_event(self) -> None:
        sink = NullAuditSink()

        with self.assertRaises(TypeError):
            sink.write("invalid")  # type: ignore[arg-type]


# ============================================================================
# SERVICE TESTS
# ============================================================================


class AuditServiceTests(SimpleTestCase):
    """Verify AuditService behavior."""

    def setUp(self) -> None:
        self.sink = RecordingAuditSink()
        self.service = AuditService(
            sink=self.sink
        )

    def test_record_creates_event(self) -> None:
        event = self.service.record(
            AuditEventType.LOGIN_SUCCESS,
            AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        self.assertIsInstance(
            event,
            AuditEvent,
        )

        self.assertEqual(
            event.event_type,
            AuditEventType.LOGIN_SUCCESS,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.SUCCESS,
        )

    def test_record_writes_to_sink(self) -> None:
        event = self.service.record(
            AuditEventType.LOGIN_SUCCESS,
            AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        self.assertEqual(
            len(self.sink.events),
            1,
        )

        self.assertIs(
            self.sink.events[0],
            event,
        )

    def test_record_preserves_actor_id(self) -> None:
        event = self.service.record(
            AuditEventType.LOGIN_SUCCESS,
            AuditOutcome.SUCCESS,
            timestamp=100.0,
            actor_id="user-1",
        )

        self.assertEqual(
            event.actor_id,
            "user-1",
        )

    def test_record_preserves_request_id(self) -> None:
        event = self.service.record(
            AuditEventType.LOGIN_SUCCESS,
            AuditOutcome.SUCCESS,
            timestamp=100.0,
            request_id="request-1",
        )

        self.assertEqual(
            event.request_id,
            "request-1",
        )

    def test_record_preserves_safe_metadata(self) -> None:
        event = self.service.record(
            AuditEventType.LOGIN_FAILURE,
            AuditOutcome.FAILURE,
            timestamp=100.0,
            metadata={
                "attempts": 3,
                "ip_address": "127.0.0.1",
            },
        )

        self.assertEqual(
            event.metadata["attempts"],
            3,
        )

        self.assertEqual(
            event.metadata["ip_address"],
            "127.0.0.1",
        )

    def test_record_rejects_sensitive_metadata(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            self.service.record(
                AuditEventType.LOGIN_FAILURE,
                AuditOutcome.FAILURE,
                timestamp=100.0,
                metadata={
                    "password": "secret",
                },
            )

        self.assertEqual(
            self.sink.events,
            [],
        )

    def test_success_helper(self) -> None:
        event = self.service.success(
            AuditEventType.LOGIN_SUCCESS,
            timestamp=100.0,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.SUCCESS,
        )

    def test_failure_helper(self) -> None:
        event = self.service.failure(
            AuditEventType.LOGIN_FAILURE,
            timestamp=100.0,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.FAILURE,
        )

    def test_denied_helper(self) -> None:
        event = self.service.denied(
            AuditEventType.RATE_LIMITED,
            timestamp=100.0,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.DENIED,
        )

    def test_warning_helper(self) -> None:
        event = self.service.warning(
            AuditEventType.SECURITY_ALERT,
            timestamp=100.0,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.WARNING,
        )

    def test_default_sink_is_available(self) -> None:
        service = AuditService()

        event = service.success(
            AuditEventType.LOGOUT,
            timestamp=100.0,
        )

        self.assertIsInstance(
            event,
            AuditEvent,
        )

    def test_invalid_event_type_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            self.service.record(
                "login_success",  # type: ignore[arg-type]
                AuditOutcome.SUCCESS,
                timestamp=100.0,
            )

    def test_invalid_outcome_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidAuditEventError
        ):
            self.service.record(
                AuditEventType.LOGIN_SUCCESS,
                "success",  # type: ignore[arg-type]
                timestamp=100.0,
            )

    def test_sink_receives_immutable_event(self) -> None:
        event = self.service.success(
            AuditEventType.WALLET_LOCKED,
            timestamp=100.0,
        )

        self.assertIs(
            self.sink.events[0],
            event,
        )

        with self.assertRaises(FrozenInstanceError):
            event.outcome = AuditOutcome.FAILURE  # type: ignore[misc]


# ============================================================================
# SECURITY EVENT TESTS
# ============================================================================


class SecurityAuditScenarioTests(SimpleTestCase):
    """Verify realistic HappyWallet security scenarios."""

    def setUp(self) -> None:
        self.sink = RecordingAuditSink()
        self.service = AuditService(
            sink=self.sink
        )

    def test_successful_login(self) -> None:
        event = self.service.success(
            AuditEventType.LOGIN_SUCCESS,
            timestamp=1_000.0,
            actor_id="user-1",
            metadata={
                "authentication_method": "password",
            },
        )

        self.assertEqual(
            event.event_type,
            AuditEventType.LOGIN_SUCCESS,
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.SUCCESS,
        )

    def test_failed_login(self) -> None:
        event = self.service.failure(
            AuditEventType.LOGIN_FAILURE,
            timestamp=1_001.0,
            actor_id="user-1",
            metadata={
                "attempt": 1,
            },
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.FAILURE,
        )

    def test_rate_limit_event(self) -> None:
        event = self.service.denied(
            AuditEventType.RATE_LIMITED,
            timestamp=1_002.0,
            actor_id="user-1",
            metadata={
                "failures": 5,
                "retry_after": 900.0,
            },
        )

        self.assertEqual(
            event.outcome,
            AuditOutcome.DENIED,
        )

    def test_wallet_lock_event(self) -> None:
        event = self.service.success(
            AuditEventType.WALLET_LOCKED,
            timestamp=1_003.0,
            actor_id="user-1",
        )

        self.assertEqual(
            event.event_type,
            AuditEventType.WALLET_LOCKED,
        )

    def test_wallet_unlock_event(self) -> None:
        event = self.service.success(
            AuditEventType.WALLET_UNLOCKED,
            timestamp=1_004.0,
            actor_id="user-1",
        )

        self.assertEqual(
            event.event_type,
            AuditEventType.WALLET_UNLOCKED,
        )

    def test_private_key_access_does_not_accept_key_material(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            self.service.success(
                AuditEventType.PRIVATE_KEY_ACCESS,
                timestamp=1_005.0,
                actor_id="user-1",
                metadata={
                    "private_key": "0x123456",
                },
            )

    def test_password_change_does_not_accept_password(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            self.service.success(
                AuditEventType.PASSWORD_CHANGED,
                timestamp=1_006.0,
                actor_id="user-1",
                metadata={
                    "password": "new-password",
                },
            )

    def test_pin_change_does_not_accept_pin(self) -> None:
        with self.assertRaises(
            UnsafeAuditMetadataError
        ):
            self.service.success(
                AuditEventType.PIN_CHANGED,
                timestamp=1_007.0,
                actor_id="user-1",
                metadata={
                    "pin": "123456",
                },
            )


# ============================================================================
# PUBLIC API TESTS
# ============================================================================


class AuditPublicAPITests(SimpleTestCase):
    """Verify the intended public API is usable."""

    def test_event_is_hashable(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.LOGOUT,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        self.assertIsInstance(
            hash(event),
            int,
        )

    def test_events_with_same_values_are_equal(self) -> None:
        first = AuditEvent(
            event_type=AuditEventType.LOGOUT,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        second = AuditEvent(
            event_type=AuditEventType.LOGOUT,
            outcome=AuditOutcome.SUCCESS,
            timestamp=100.0,
        )

        self.assertEqual(
            first,
            second,
        )

    def test_event_metadata_is_copied(self) -> None:
        metadata = {
            "attempt": 1,
        }

        event = AuditEvent(
            event_type=AuditEventType.LOGIN_FAILURE,
            outcome=AuditOutcome.FAILURE,
            timestamp=100.0,
            metadata=metadata,
        )

        metadata["attempt"] = 99

        self.assertEqual(
            event.metadata["attempt"],
            1,
        )