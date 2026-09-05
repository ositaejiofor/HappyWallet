"""HappyWallet USB transport protocol.

Defines the communication format between:

    ONLINE DESKTOP WALLET
              ↕
          USB MEDIA
              ↕
       OFFLINE SIGNER

Security principles:

- Private keys are never transported.
- Mnemonics and seed material are never transported.
- Encryption keys are never transported.
- Transport contains public/transaction data only.
- Every message is versioned.
- Every message has a unique request ID.
- Every message is integrity protected with SHA-256.
- Unknown message types are rejected.
- Malformed messages are rejected.
- Oversized messages are rejected.
- Transport never broadcasts transactions.

This module defines the protocol only.
It does not perform USB I/O.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any


# ============================================================================
# CONSTANTS
# ============================================================================

PROTOCOL_NAME = "happywallet-usb"
PROTOCOL_VERSION = 1

MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MiB

HASH_ALGORITHM = "sha256"

_ALLOWED_SESSION_ROLES = frozenset(
    {
        "desktop",
        "signer",
    }
)

_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "private_key",
        "privatekey",
        "privkey",
        "private",
        "secret",
        "secret_key",
        "secretkey",
        "seed",
        "seed_material",
        "seedphrase",
        "seed_phrase",
        "mnemonic",
        "mnemonic_phrase",
        "extended_private_key",
        "extendedprivatekey",
        "xprv",
        "yprv",
        "zprv",
        "raw_private_key",
        "rawprivatekey",
        "encryption_key",
        "encryptionkey",
        "master_key",
        "masterkey",
        "master_seed",
        "masterseed",
    }
)


# ============================================================================
# EXCEPTIONS
# ============================================================================


class TransportError(Exception):
    """Base exception for transport errors."""


class InvalidTransportMessage(TransportError):
    """Raised when a transport message is malformed."""


class UnsupportedProtocolVersion(TransportError):
    """Raised when an unsupported protocol version is received."""


class UnsupportedMessageType(TransportError):
    """Raised when an unknown message type is received."""


class TransportSecurityError(TransportError):
    """Raised when a transport security rule is violated."""


# ============================================================================
# MESSAGE TYPES
# ============================================================================


class MessageType(str, Enum):
    """Supported HappyWallet USB transport message types."""

    HELLO = "hello"
    DEVICE_INFO = "device_info"

    WALLET_INFO_REQUEST = "wallet_info_request"
    WALLET_INFO_RESPONSE = "wallet_info_response"

    TRANSACTION_REQUEST = "transaction_request"
    TRANSACTION_REVIEW = "transaction_review"

    SIGN_REQUEST = "sign_request"
    SIGN_RESPONSE = "sign_response"

    ERROR = "error"
    ACK = "ack"


# ============================================================================
# MESSAGE
# ============================================================================


@dataclass(frozen=True, slots=True)
class TransportMessage:
    """A single validated HappyWallet transport message.

    Payloads must contain public/non-secret information only.
    """

    message_type: MessageType
    request_id: str
    payload: dict[str, Any]

    protocol: str = PROTOCOL_NAME
    version: int = PROTOCOL_VERSION
    checksum: str | None = None

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def validate(self) -> None:
        """Validate protocol structure and payload security."""

        if self.protocol != PROTOCOL_NAME:
            raise InvalidTransportMessage(
                "Invalid transport protocol."
            )

        if not isinstance(self.version, int) or isinstance(
            self.version,
            bool,
        ):
            raise InvalidTransportMessage(
                "Protocol version must be an integer."
            )

        if self.version != PROTOCOL_VERSION:
            raise UnsupportedProtocolVersion(
                f"Unsupported protocol version: {self.version}"
            )

        if not isinstance(self.message_type, MessageType):
            raise UnsupportedMessageType(
                "Unsupported message type."
            )

        if not isinstance(self.request_id, str):
            raise InvalidTransportMessage(
                "Request ID must be a string."
            )

        if not self.request_id.strip():
            raise InvalidTransportMessage(
                "Request ID cannot be empty."
            )

        if not isinstance(self.payload, dict):
            raise InvalidTransportMessage(
                "Message payload must be an object."
            )

        self._validate_payload_security()

    # ------------------------------------------------------------------------
    # SECURITY
    # ------------------------------------------------------------------------

    def _validate_payload_security(self) -> None:
        """Reject sensitive wallet material from transport payloads."""

        self._scan_for_forbidden_keys(
            self.payload,
            path="payload",
        )

    @classmethod
    def _scan_for_forbidden_keys(
        cls,
        value: Any,
        *,
        path: str,
    ) -> None:
        """Recursively inspect mappings and sequences for forbidden keys."""

        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).strip().lower()

                if normalized in _FORBIDDEN_FIELD_NAMES:
                    raise TransportSecurityError(
                        f"Sensitive field '{path}.{key}' "
                        "cannot be transmitted."
                    )

                cls._scan_for_forbidden_keys(
                    child,
                    path=f"{path}.{key}",
                )

            return

        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                cls._scan_for_forbidden_keys(
                    child,
                    path=f"{path}[{index}]",
                )

    # ------------------------------------------------------------------------
    # CANONICAL DOCUMENT
    # ------------------------------------------------------------------------

    def _document_without_checksum(self) -> dict[str, Any]:
        """Return the canonical message document without its checksum."""

        self.validate()

        return {
            "protocol": self.protocol,
            "version": self.version,
            "message_type": self.message_type.value,
            "request_id": self.request_id,
            "payload": self.payload,
        }

    # ------------------------------------------------------------------------
    # SERIALIZATION
    # ------------------------------------------------------------------------

    def to_dict(
        self,
        *,
        include_checksum: bool = True,
    ) -> dict[str, Any]:
        """Convert the message into a JSON-compatible dictionary."""

        document = self._document_without_checksum()

        if include_checksum:
            document["checksum"] = (
                self.checksum
                if self.checksum is not None
                else self.calculate_checksum()
            )

        return document

    # ------------------------------------------------------------------------
    # CHECKSUM
    # ------------------------------------------------------------------------

    def calculate_checksum(self) -> str:
        """Calculate the deterministic SHA-256 message checksum."""

        canonical = json.dumps(
            self._document_without_checksum(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return hashlib.sha256(canonical).hexdigest()

    def verify_checksum(self) -> bool:
        """Return True when the stored checksum matches the message."""

        if not isinstance(self.checksum, str):
            return False

        if len(self.checksum) != 64:
            return False

        try:
            int(self.checksum, 16)
        except ValueError:
            return False

        expected = self.calculate_checksum()

        return secrets.compare_digest(
            expected,
            self.checksum,
        )

    # ------------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------------

    def to_json(self) -> bytes:
        """Serialize the message to UTF-8 JSON bytes."""

        document = self.to_dict()

        try:
            raw = json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise InvalidTransportMessage(
                "Transport message contains non-JSON-serializable data."
            ) from exc

        if len(raw) > MAX_MESSAGE_SIZE:
            raise InvalidTransportMessage(
                "Transport message exceeds maximum size."
            )

        return raw

    # ------------------------------------------------------------------------
    # DESERIALIZATION
    # ------------------------------------------------------------------------

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "TransportMessage":
        """Construct and fully validate a message from a dictionary."""

        if not isinstance(document, dict):
            raise InvalidTransportMessage(
                "Transport message must be an object."
            )

        try:
            protocol = document["protocol"]
            version = document["version"]
            raw_message_type = document["message_type"]
            request_id = document["request_id"]
            payload = document["payload"]
            checksum = document["checksum"]

        except KeyError as exc:
            raise InvalidTransportMessage(
                f"Missing transport message field: {exc.args[0]}"
            ) from exc

        if not isinstance(protocol, str):
            raise InvalidTransportMessage(
                "Transport protocol must be a string."
            )

        if not isinstance(version, int) or isinstance(version, bool):
            raise InvalidTransportMessage(
                "Transport protocol version must be an integer."
            )

        try:
            message_type = MessageType(raw_message_type)
        except (TypeError, ValueError) as exc:
            raise UnsupportedMessageType(
                "Unsupported message type."
            ) from exc

        if not isinstance(request_id, str):
            raise InvalidTransportMessage(
                "Request ID must be a string."
            )

        if not isinstance(payload, dict):
            raise InvalidTransportMessage(
                "Message payload must be an object."
            )

        if not isinstance(checksum, str):
            raise InvalidTransportMessage(
                "Transport message checksum is required."
            )

        message = cls(
            protocol=protocol,
            version=version,
            message_type=message_type,
            request_id=request_id,
            payload=payload,
            checksum=checksum,
        )

        message.validate()

        if not message.verify_checksum():
            raise InvalidTransportMessage(
                "Transport checksum verification failed."
            )

        return message

    @classmethod
    def from_json(
        cls,
        raw: bytes,
    ) -> "TransportMessage":
        """Deserialize and validate UTF-8 JSON transport data."""

        if not isinstance(raw, bytes):
            raise TypeError(
                "Transport data must be bytes."
            )

        if not raw:
            raise InvalidTransportMessage(
                "Transport message is empty."
            )

        if len(raw) > MAX_MESSAGE_SIZE:
            raise InvalidTransportMessage(
                "Transport message exceeds maximum size."
            )

        try:
            document = json.loads(
                raw.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise InvalidTransportMessage(
                "Transport message is not valid JSON."
            ) from exc

        return cls.from_dict(document)


# ============================================================================
# FACTORY
# ============================================================================


class TransportFactory:
    """Factory for creating validated transport messages."""

    @staticmethod
    def request_id() -> str:
        """Generate a cryptographically random request ID."""

        return secrets.token_hex(16)

    @classmethod
    def create(
        cls,
        message_type: MessageType,
        payload: dict[str, Any],
        *,
        request_id: str | None = None,
    ) -> TransportMessage:
        """Create a validated, checksum-protected transport message."""

        if not isinstance(message_type, MessageType):
            raise UnsupportedMessageType(
                "Invalid message type."
            )

        if not isinstance(payload, dict):
            raise InvalidTransportMessage(
                "Payload must be a dictionary."
            )

        if request_id is None:
            request_id = cls.request_id()
        elif not isinstance(request_id, str):
            raise InvalidTransportMessage(
                "Request ID must be a string."
            )
        elif not request_id.strip():
            raise InvalidTransportMessage(
                "Request ID cannot be empty."
            )

        message = TransportMessage(
            message_type=message_type,
            request_id=request_id,
            payload=payload,
        )

        message.validate()

        checksum = message.calculate_checksum()

        return TransportMessage(
            message_type=message.message_type,
            request_id=message.request_id,
            payload=message.payload,
            protocol=message.protocol,
            version=message.version,
            checksum=checksum,
        )


# ============================================================================
# REQUEST BUILDERS
# ============================================================================


class TransportRequests:
    """Standard messages generated by the online desktop wallet."""

    @staticmethod
    def hello(
        device_name: str = "HappyWallet Desktop",
    ) -> TransportMessage:
        """Begin communication with the offline signer."""

        if not isinstance(device_name, str):
            raise TypeError(
                "device_name must be a string."
            )

        device_name = device_name.strip()

        if not device_name:
            raise ValueError(
                "device_name cannot be empty."
            )

        return TransportFactory.create(
            MessageType.HELLO,
            {
                "device_name": device_name,
                "client": "desktop",
                "protocol": PROTOCOL_NAME,
                "protocol_version": PROTOCOL_VERSION,
            },
        )

    @staticmethod
    def wallet_info() -> TransportMessage:
        """Request public wallet information."""

        return TransportFactory.create(
            MessageType.WALLET_INFO_REQUEST,
            {},
        )

    @staticmethod
    def transaction(
        *,
        network: str,
        transaction: dict[str, Any],
    ) -> TransportMessage:
        """Send an unsigned public transaction to the offline signer."""

        if not isinstance(network, str):
            raise TypeError(
                "network must be a string."
            )

        network = network.strip().lower()

        if not network:
            raise ValueError(
                "Network is required."
            )

        if not isinstance(transaction, dict):
            raise TypeError(
                "transaction must be a dictionary."
            )

        if not transaction:
            raise ValueError(
                "Transaction cannot be empty."
            )

        return TransportFactory.create(
            MessageType.TRANSACTION_REQUEST,
            {
                "network": network,
                "transaction": transaction,
            },
        )

    @staticmethod
    def sign(
        *,
        network: str,
        transaction_hash: str,
    ) -> TransportMessage:
        """Request signing of an already identified transaction."""

        if not isinstance(network, str):
            raise TypeError(
                "network must be a string."
            )

        network = network.strip().lower()

        if not network:
            raise ValueError(
                "Network is required."
            )

        if not isinstance(transaction_hash, str):
            raise TypeError(
                "transaction_hash must be a string."
            )

        transaction_hash = transaction_hash.strip()

        if not transaction_hash:
            raise ValueError(
                "Transaction hash is required."
            )

        return TransportFactory.create(
            MessageType.SIGN_REQUEST,
            {
                "network": network,
                "transaction_hash": transaction_hash,
            },
        )


# ============================================================================
# RESPONSE BUILDERS
# ============================================================================


class TransportResponses:
    """Standard messages generated by the offline signer."""

    @staticmethod
    def ack(
        request_id: str,
        *,
        message: str = "OK",
    ) -> TransportMessage:
        """Acknowledge a request."""

        return TransportFactory.create(
            MessageType.ACK,
            {
                "message": message,
            },
            request_id=request_id,
        )

    @staticmethod
    def device_info(
        request_id: str,
        *,
        device_id: str,
        firmware_version: str,
        protocol_version: int = PROTOCOL_VERSION,
    ) -> TransportMessage:
        """Return public offline-device information."""

        return TransportFactory.create(
            MessageType.DEVICE_INFO,
            {
                "device_id": device_id,
                "firmware_version": firmware_version,
                "protocol_version": protocol_version,
            },
            request_id=request_id,
        )

    @staticmethod
    def wallet_info(
        request_id: str,
        *,
        wallet_name: str,
        network: str,
        addresses: list[str],
    ) -> TransportMessage:
        """Return public wallet information."""

        return TransportFactory.create(
            MessageType.WALLET_INFO_RESPONSE,
            {
                "wallet_name": wallet_name,
                "network": network,
                "addresses": addresses,
            },
            request_id=request_id,
        )

    @staticmethod
    def transaction_review(
        request_id: str,
        *,
        network: str,
        recipient: str,
        amount: str,
        asset: str,
        fee: str | None = None,
    ) -> TransportMessage:
        """Return transaction information for user confirmation."""

        payload: dict[str, Any] = {
            "network": network,
            "recipient": recipient,
            "amount": amount,
            "asset": asset,
        }

        if fee is not None:
            payload["fee"] = fee

        return TransportFactory.create(
            MessageType.TRANSACTION_REVIEW,
            payload,
            request_id=request_id,
        )

    @staticmethod
    def sign(
        request_id: str,
        *,
        network: str,
        transaction_hash: str,
        signature: str,
    ) -> TransportMessage:
        """Return a transaction signature without exposing the private key."""

        return TransportFactory.create(
            MessageType.SIGN_RESPONSE,
            {
                "network": network,
                "transaction_hash": transaction_hash,
                "signature": signature,
            },
            request_id=request_id,
        )

    @staticmethod
    def error(
        request_id: str,
        *,
        code: str,
        message: str,
    ) -> TransportMessage:
        """Return a safe protocol error response."""

        return TransportFactory.create(
            MessageType.ERROR,
            {
                "code": code,
                "message": message,
            },
            request_id=request_id,
        )


# ============================================================================
# TRANSPORT SESSION
# ============================================================================


class TransportSession:
    """Stateful protocol session.

    This class performs protocol validation only.
    It does not perform USB I/O.

    Request IDs are tracked to prevent the same request from being
    prepared repeatedly. Incoming messages are validated independently.
    """

    def __init__(
        self,
        *,
        role: str,
    ) -> None:
        if not isinstance(role, str):
            raise TypeError(
                "role must be a string."
            )

        role = role.strip().lower()

        if role not in _ALLOWED_SESSION_ROLES:
            raise ValueError(
                "role must be 'desktop' or 'signer'."
            )

        self.role = role
        self.session_id = secrets.token_hex(16)

        self._closed = False
        self._requests: set[str] = set()

    @property
    def closed(self) -> bool:
        """Return True when the session has been closed."""

        return self._closed

    def close(self) -> None:
        """Close the transport session and clear request state."""

        self._closed = True
        self._requests.clear()

    def prepare(
        self,
        message: TransportMessage,
    ) -> bytes:
        """Validate and serialize an outgoing message."""

        if self._closed:
            raise TransportError(
                "Transport session is closed."
            )

        if not isinstance(message, TransportMessage):
            raise TypeError(
                "message must be a TransportMessage."
            )

        message.validate()

        if message.request_id in self._requests:
            raise TransportError(
                "Duplicate request ID."
            )

        self._requests.add(
            message.request_id
        )

        return message.to_json()

    def receive(
        self,
        raw: bytes,
    ) -> TransportMessage:
        """Deserialize and validate an incoming message."""

        if self._closed:
            raise TransportError(
                "Transport session is closed."
            )

        return TransportMessage.from_json(raw)


# ============================================================================
# TRANSACTION DIGEST
# ============================================================================


def transaction_digest(
    transaction: dict[str, Any],
) -> str:
    """Calculate a deterministic SHA-256 transaction digest.

    The transaction is security-validated before hashing so private
    wallet material cannot be included accidentally.
    """

    if not isinstance(transaction, dict):
        raise TypeError(
            "Transaction must be a dictionary."
        )

    if not transaction:
        raise ValueError(
            "Transaction cannot be empty."
        )

    validation_message = TransportMessage(
        message_type=MessageType.TRANSACTION_REQUEST,
        request_id="digest-validation",
        payload={
            "transaction": transaction,
        },
    )

    validation_message.validate()

    canonical = json.dumps(
        transaction,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(
        canonical
    ).hexdigest()


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "MAX_MESSAGE_SIZE",
    "HASH_ALGORITHM",
    "TransportError",
    "InvalidTransportMessage",
    "UnsupportedProtocolVersion",
    "UnsupportedMessageType",
    "TransportSecurityError",
    "MessageType",
    "TransportMessage",
    "TransportFactory",
    "TransportRequests",
    "TransportResponses",
    "TransportSession",
    "transaction_digest",
]
