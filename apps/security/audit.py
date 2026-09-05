"""
HappyWallet Security Audit Service.

Security boundary
-----------------

    Security-sensitive operation
              |
              v
         AuditService
              |
       +------+------+ 
       |             |
    Event         Metadata
       |             |
       +------+------+ 
              |
              v
        AuditSink

Responsibilities
----------------

This module owns:

    - security audit event definitions
    - audit event validation
    - immutable audit records
    - safe metadata normalization
    - audit event creation
    - pluggable event sinks

This module deliberately does NOT know about:

    - Django models
    - HTTP requests
    - sessions
    - templates
    - database persistence
    - wallets
    - private keys
    - passwords
    - PINs
    - encryption
    - blockchain RPC
    - filesystem persistence

Security properties
-------------------

    - audit records are immutable
    - audit metadata is immutable
    - plaintext passwords are never accepted as metadata
    - plaintext PINs are never accepted as metadata
    - private keys are never accepted as metadata
    - seed phrases are never accepted as metadata
    - sensitive metadata keys are rejected
    - metadata values are restricted to primitive types
    - event types are explicitly enumerated
    - timestamps are normalized to float
    - actor/request identifiers are normalized
    - audit events are safely hashable
    - persistence is delegated to an audit sink
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final, Mapping, Protocol


# ============================================================================
# TYPE ALIASES
# ============================================================================

AuditMetadataValue = str | int | float | bool | None


# ============================================================================
# EXCEPTIONS
# ============================================================================


class AuditSecurityError(Exception):
    """Base exception for security-audit failures."""


class InvalidAuditEventError(AuditSecurityError):
    """Raised when an audit event is malformed or unsafe."""


class UnsafeAuditMetadataError(AuditSecurityError):
    """Raised when audit metadata contains sensitive credential material."""


# ============================================================================
# EVENT TYPES
# ============================================================================


class AuditEventType(str, Enum):
    """
    Supported security audit events.

    Event names are deliberately explicit so callers cannot accidentally
    create arbitrary security-event categories.
    """

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"

    PASSWORD_CHANGED = "password_changed"
    PASSWORD_VERIFICATION_FAILED = "password_verification_failed"

    PIN_CHANGED = "pin_changed"
    PIN_VERIFICATION_FAILED = "pin_verification_failed"

    RATE_LIMITED = "rate_limited"

    WALLET_CREATED = "wallet_created"
    WALLET_IMPORTED = "wallet_imported"
    WALLET_EXPORTED = "wallet_exported"

    WALLET_LOCKED = "wallet_locked"
    WALLET_UNLOCKED = "wallet_unlocked"

    VAULT_LOCKED = "vault_locked"
    VAULT_UNLOCKED = "vault_unlocked"

    PRIVATE_KEY_ACCESS = "private_key_access"

    TRANSACTION_SIGNING_STARTED = "transaction_signing_started"
    TRANSACTION_SIGNING_FAILED = "transaction_signing_failed"
    TRANSACTION_SIGNING_SUCCEEDED = "transaction_signing_succeeded"

    TRANSACTION_BROADCAST_STARTED = "transaction_broadcast_started"
    TRANSACTION_BROADCAST_FAILED = "transaction_broadcast_failed"
    TRANSACTION_BROADCAST_SUCCEEDED = "transaction_broadcast_succeeded"

    SECURITY_SETTING_CHANGED = "security_setting_changed"

    USB_VAULT_CONNECTED = "usb_vault_connected"
    USB_VAULT_DISCONNECTED = "usb_vault_disconnected"

    SECURITY_ALERT = "security_alert"


# ============================================================================
# AUDIT OUTCOME
# ============================================================================


class AuditOutcome(str, Enum):
    """Outcome of an audited security operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    WARNING = "warning"


# ============================================================================
# SAFE METADATA
# ============================================================================


_FORBIDDEN_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "pin",
        "otp",
        "totp",
        "secret",
        "private_key",
        "privatekey",
        "seed",
        "seed_phrase",
        "mnemonic",
        "mnemonic_phrase",
        "recovery_phrase",
        "recovery_seed",
        "xprv",
        "extended_private_key",
        "wallet_secret",
        "vault_secret",
        "encryption_key",
        "decryption_key",
        "api_key",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "session_key",
    }
)


def _normalize_metadata_key(key: object) -> str:
    """
    Normalize a metadata key for security validation.

    Keys are stripped and case-folded so variations such as:

        PASSWORD
        Password
        " password "

    are treated identically.
    """

    if not isinstance(key, str):
        raise UnsafeAuditMetadataError(
            "Audit metadata keys must be strings."
        )

    normalized = key.strip().casefold()

    if not normalized:
        raise UnsafeAuditMetadataError(
            "Audit metadata keys cannot be empty."
        )

    return normalized


def _validate_metadata_value(
    key: str,
    value: object,
) -> None:
    """
    Validate an audit metadata value.

    Audit metadata deliberately supports only primitive values.
    Arbitrary objects, mappings and collections are rejected.
    """

    if isinstance(value, (str, int, float, bool)) or value is None:
        return

    raise UnsafeAuditMetadataError(
        f"Unsupported audit metadata value for key '{key}'."
    )


def sanitize_metadata(
    metadata: Mapping[str, object] | None,
) -> dict[str, AuditMetadataValue]:
    """
    Validate and defensively copy audit metadata.

    Sensitive credential fields are rejected rather than silently
    redacted. This prevents callers from accidentally believing that
    unsafe information was successfully recorded.

    Returns
    -------
    dict[str, AuditMetadataValue]
        A new, normalized dictionary.

    Notes
    -----
    The returned dictionary is subsequently wrapped in MappingProxyType
    by AuditEvent, making event metadata immutable.
    """

    if metadata is None:
        return {}

    if not isinstance(metadata, Mapping):
        raise TypeError(
            "Audit metadata must be a mapping or None."
        )

    sanitized: dict[str, AuditMetadataValue] = {}

    for key, value in metadata.items():
        normalized_key = _normalize_metadata_key(key)

        if normalized_key in _FORBIDDEN_METADATA_KEYS:
            raise UnsafeAuditMetadataError(
                "Sensitive audit metadata key is forbidden: "
                f"{normalized_key}."
            )

        _validate_metadata_value(
            normalized_key,
            value,
        )

        sanitized[normalized_key] = value

    return sanitized


# ============================================================================
# AUDIT EVENT
# ============================================================================


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """
    Immutable security audit event.

    Security properties
    -------------------

    - Event fields cannot be reassigned.
    - Metadata is defensively copied.
    - Metadata cannot be mutated after construction.
    - Sensitive metadata is rejected during validation.
    - Metadata is restricted to primitive audit-safe values.
    - The event is safely hashable.
    """

    event_type: AuditEventType
    outcome: AuditOutcome
    timestamp: float

    actor_id: str | None = None
    request_id: str | None = None

    metadata: Mapping[str, AuditMetadataValue] = field(
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        """
        Validate and normalize the audit event.

        Validation remains inside the domain object so an AuditEvent
        can never exist in an invalid state.
        """

        # ------------------------------------------------------------------
        # EVENT TYPE
        # ------------------------------------------------------------------

        if not isinstance(
            self.event_type,
            AuditEventType,
        ):
            raise InvalidAuditEventError(
                "Invalid audit event type."
            )

        # ------------------------------------------------------------------
        # OUTCOME
        # ------------------------------------------------------------------

        if not isinstance(
            self.outcome,
            AuditOutcome,
        ):
            raise InvalidAuditEventError(
                "Invalid audit outcome."
            )

        # ------------------------------------------------------------------
        # TIMESTAMP
        # ------------------------------------------------------------------

        # bool is a subclass of int, therefore it must be explicitly
        # rejected before accepting numeric timestamps.
        if isinstance(self.timestamp, bool):
            raise InvalidAuditEventError(
                "Audit timestamp must be a number."
            )

        if not isinstance(
            self.timestamp,
            (int, float),
        ):
            raise InvalidAuditEventError(
                "Audit timestamp must be a number."
            )

        if self.timestamp < 0:
            raise InvalidAuditEventError(
                "Audit timestamp cannot be negative."
            )

        # Canonical timestamp representation.
        normalized_timestamp = float(
            self.timestamp
        )

        object.__setattr__(
            self,
            "timestamp",
            normalized_timestamp,
        )

        # ------------------------------------------------------------------
        # ACTOR ID
        # ------------------------------------------------------------------

        if self.actor_id is not None:
            if not isinstance(
                self.actor_id,
                str,
            ):
                raise InvalidAuditEventError(
                    "Actor ID must be a string or None."
                )

            normalized_actor_id = self.actor_id.strip()

            if not normalized_actor_id:
                raise InvalidAuditEventError(
                    "Actor ID cannot be empty."
                )

            object.__setattr__(
                self,
                "actor_id",
                normalized_actor_id,
            )

        # ------------------------------------------------------------------
        # REQUEST ID
        # ------------------------------------------------------------------

        if self.request_id is not None:
            if not isinstance(
                self.request_id,
                str,
            ):
                raise InvalidAuditEventError(
                    "Request ID must be a string or None."
                )

            normalized_request_id = self.request_id.strip()

            if not normalized_request_id:
                raise InvalidAuditEventError(
                    "Request ID cannot be empty."
                )

            object.__setattr__(
                self,
                "request_id",
                normalized_request_id,
            )

        # ------------------------------------------------------------------
        # METADATA
        # ------------------------------------------------------------------

        normalized_metadata = sanitize_metadata(
            self.metadata
        )

        # MappingProxyType provides runtime immutability.
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                normalized_metadata
            ),
        )

    def __hash__(self) -> int:
        """
        Return a deterministic hash for the immutable audit event.

        Mapping objects are not directly hashable. Metadata is converted
        into a sorted tuple of key/value pairs before hashing.

        The metadata schema permits only primitive values, so the
        resulting representation is safely hashable.
        """

        metadata_items = tuple(
            sorted(
                self.metadata.items(),
                key=lambda item: item[0],
            )
        )

        return hash(
            (
                self.event_type,
                self.outcome,
                self.timestamp,
                self.actor_id,
                self.request_id,
                metadata_items,
            )
        )


# ============================================================================
# AUDIT SINK
# ============================================================================


class AuditSink(Protocol):
    """
    Protocol implemented by persistence adapters.

    Examples:

        DatabaseAuditSink
        FileAuditSink
        StructuredLoggingAuditSink
        SIEMAuditSink
    """

    def write(
        self,
        event: AuditEvent,
    ) -> None:
        """Persist or forward an audit event."""


# ============================================================================
# NULL SINK
# ============================================================================


class NullAuditSink:
    """
    No-op audit sink.

    Useful as the default dependency for domain-level tests and for
    applications which configure their persistence adapter elsewhere.
    """

    def write(
        self,
        event: AuditEvent,
    ) -> None:
        """Accept an event without persisting it."""

        if not isinstance(
            event,
            AuditEvent,
        ):
            raise TypeError(
                "Audit sink requires an AuditEvent."
            )


# ============================================================================
# AUDIT SERVICE
# ============================================================================


class AuditService:
    """
    Stateless security audit service.

    The service creates immutable AuditEvent instances and delegates
    persistence to an injected AuditSink.

    It never stores passwords, PINs, private keys, seed phrases,
    or other credential material.
    """

    def __init__(
        self,
        sink: AuditSink | None = None,
    ) -> None:
        self._sink = (
            sink
            if sink is not None
            else NullAuditSink()
        )

    # ========================================================================
    # EVENT CREATION
    # ========================================================================

    def record(
        self,
        event_type: AuditEventType,
        outcome: AuditOutcome,
        *,
        timestamp: float,
        actor_id: str | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """
        Create and write an audit event.

        Returns the immutable event after it has been passed to the sink.
        """

        if not isinstance(
            event_type,
            AuditEventType,
        ):
            raise InvalidAuditEventError(
                "Event type must be an AuditEventType."
            )

        if not isinstance(
            outcome,
            AuditOutcome,
        ):
            raise InvalidAuditEventError(
                "Outcome must be an AuditOutcome."
            )

        event = AuditEvent(
            event_type=event_type,
            outcome=outcome,
            timestamp=timestamp,
            actor_id=actor_id,
            request_id=request_id,
            metadata=metadata or {},
        )

        self._sink.write(event)

        return event

    # ========================================================================
    # SUCCESS
    # ========================================================================

    def success(
        self,
        event_type: AuditEventType,
        *,
        timestamp: float,
        actor_id: str | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Record a successful security operation."""

        return self.record(
            event_type,
            AuditOutcome.SUCCESS,
            timestamp=timestamp,
            actor_id=actor_id,
            request_id=request_id,
            metadata=metadata,
        )

    # ========================================================================
    # FAILURE
    # ========================================================================

    def failure(
        self,
        event_type: AuditEventType,
        *,
        timestamp: float,
        actor_id: str | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Record a failed security operation."""

        return self.record(
            event_type,
            AuditOutcome.FAILURE,
            timestamp=timestamp,
            actor_id=actor_id,
            request_id=request_id,
            metadata=metadata,
        )

    # ========================================================================
    # DENIED
    # ========================================================================

    def denied(
        self,
        event_type: AuditEventType,
        *,
        timestamp: float,
        actor_id: str | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Record a denied security operation."""

        return self.record(
            event_type,
            AuditOutcome.DENIED,
            timestamp=timestamp,
            actor_id=actor_id,
            request_id=request_id,
            metadata=metadata,
        )

    # ========================================================================
    # WARNING
    # ========================================================================

    def warning(
        self,
        event_type: AuditEventType,
        *,
        timestamp: float,
        actor_id: str | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Record a security warning."""

        return self.record(
            event_type,
            AuditOutcome.WARNING,
            timestamp=timestamp,
            actor_id=actor_id,
            request_id=request_id,
            metadata=metadata,
        )


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditMetadataValue",
    "AuditOutcome",
    "AuditSecurityError",
    "AuditService",
    "AuditSink",
    "InvalidAuditEventError",
    "NullAuditSink",
    "UnsafeAuditMetadataError",
    "sanitize_metadata",
]