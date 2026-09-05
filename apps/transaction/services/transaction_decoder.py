"""
HappyWallet Transaction Decoder.

Security boundary
-----------------

This module decodes and structurally validates HappyWallet's generic
transaction representation.

It does NOT:

    - access private keys
    - access mnemonics
    - decrypt wallet secrets
    - sign transactions
    - serialize network-native transactions
    - broadcast transactions
    - communicate with blockchain RPC endpoints
    - modify wallet records
    - persist transaction data

Architecture
------------

    TransactionBuilder
            |
            v
    canonical application payload
            |
            v
    TransactionDecoder
            |
            v
    DecodedTransaction
            |
            +----> validation / auditing
            |
            +----> SigningService
            |
            +----> TransactionEncoder
            |
            +----> TransactionBroadcaster

IMPORTANT

The canonical JSON representation handled here is an application-level
transaction representation.

It is NOT:

    - Ethereum RLP
    - Ethereum EIP-1559 signed transaction bytes
    - Bitcoin raw transaction bytes
    - Bitcoin PSBT
    - TRON protobuf transaction bytes
    - a signed blockchain transaction

Network-specific serialization belongs to TransactionEncoder and the
corresponding network serializer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Final, Mapping


# ============================================================================
# EXCEPTIONS
# ============================================================================


class TransactionDecodeError(Exception):
    """Base exception for transaction decoding errors."""


class InvalidTransactionPayloadError(TransactionDecodeError):
    """Raised when the serialized transaction payload is invalid."""


class UnsupportedTransactionNetworkError(TransactionDecodeError):
    """Raised when the transaction network is unsupported."""


class InvalidTransactionFieldError(TransactionDecodeError):
    """Raised when a transaction field is invalid."""


# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass(frozen=True)
class DecodedTransaction:
    """
    Immutable representation of a decoded application transaction.

    `payload_hash` is the SHA-256 hash of the exact serialized application
    payload. It is NOT a blockchain transaction hash.

    Blockchain transaction hashes must be produced by the appropriate
    network serialization/broadcasting layer.
    """

    network: str
    transaction_type: str
    payload: dict[str, Any]
    payload_hash: str

    @property
    def nonce(self) -> int | None:
        """Return the optional transaction nonce."""

        value = self.payload.get("nonce")

        if value is None:
            return None

        try:
            return int(value)

        except (TypeError, ValueError) as exc:
            raise InvalidTransactionFieldError(
                "nonce must be an integer-compatible value."
            ) from exc

    @property
    def sender(self) -> str | None:
        """Return the optional sender address."""

        value = self.payload.get("from")

        if value is None:
            return None

        if not isinstance(value, str):
            raise InvalidTransactionFieldError(
                "from must be a string."
            )

        return value

    @property
    def recipient(self) -> str | None:
        """Return the optional recipient address."""

        value = self.payload.get("to")

        if value is None:
            return None

        if not isinstance(value, str):
            raise InvalidTransactionFieldError(
                "to must be a string."
            )

        return value

    @property
    def value(self) -> Decimal | None:
        """
        Return the transaction value as Decimal.

        No assumption is made here about the blockchain denomination.
        Network-specific interpretation belongs to the network layer.
        """

        value = self.payload.get("value")

        if value is None:
            return None

        try:
            return Decimal(str(value))

        except (InvalidOperation, ValueError, TypeError) as exc:
            raise InvalidTransactionFieldError(
                "value must be a valid decimal value."
            ) from exc

    @property
    def data(self) -> str | None:
        """Return optional transaction data."""

        value = self.payload.get("data")

        if value is None:
            return None

        if not isinstance(value, str):
            raise InvalidTransactionFieldError(
                "data must be a string."
            )

        return value

    @property
    def chain_id(self) -> int | str | None:
        """
        Return the optional chain identifier.

        Chain-specific validation is intentionally delegated to the
        corresponding network layer.
        """

        return self.payload.get("chain_id")


# ============================================================================
# TRANSACTION DECODER
# ============================================================================


class TransactionDecoder:
    """
    Decode HappyWallet's canonical application transaction representation.

    This class performs generic structural validation only.

    It deliberately does not perform blockchain-specific validation such as:

        - Ethereum address validation
        - Ethereum nonce/state validation
        - EIP-1559 fee validation
        - Bitcoin UTXO validation
        - TRON account validation
        - signature validation
        - balance validation

    Those responsibilities belong to their respective network layers.
    """

    HASH_ALGORITHM: Final = "SHA-256"

    SUPPORTED_NETWORKS: Final[frozenset[str]] = frozenset(
        {
            "ethereum",
            "bitcoin",
            "tron",
        }
    )

    NETWORK_ALIASES: Final[dict[str, str]] = {
        "eth": "ethereum",
        "btc": "bitcoin",
        "trx": "tron",
    }

    REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "network",
            "transaction_type",
        }
    )

    # ========================================================================
    # NETWORK
    # ========================================================================

    @classmethod
    def normalize_network(
        cls,
        network: str,
    ) -> str:
        """
        Normalize and validate a blockchain network identifier.
        """

        if not isinstance(network, str):
            raise UnsupportedTransactionNetworkError(
                "Network must be a string."
            )

        normalized = network.strip().lower()

        if not normalized:
            raise UnsupportedTransactionNetworkError(
                "Network cannot be empty."
            )

        normalized = cls.NETWORK_ALIASES.get(
            normalized,
            normalized,
        )

        if normalized not in cls.SUPPORTED_NETWORKS:
            raise UnsupportedTransactionNetworkError(
                f"Unsupported transaction network: {network}"
            )

        return normalized

    # ========================================================================
    # TRANSACTION TYPE
    # ========================================================================

    @staticmethod
    def normalize_transaction_type(
        transaction_type: str,
    ) -> str:
        """
        Normalize a transaction type.

        Only generic structural validation is performed here.
        """

        if not isinstance(transaction_type, str):
            raise InvalidTransactionFieldError(
                "transaction_type must be a string."
            )

        normalized = transaction_type.strip().lower()

        if not normalized:
            raise InvalidTransactionFieldError(
                "transaction_type cannot be empty."
            )

        return normalized

    # ========================================================================
    # UTF-8
    # ========================================================================

    @staticmethod
    def _decode_utf8(
        payload: bytes,
    ) -> str:
        """
        Decode transaction bytes as UTF-8.
        """

        try:
            return payload.decode("utf-8")

        except UnicodeDecodeError as exc:
            raise InvalidTransactionPayloadError(
                "Transaction payload is not valid UTF-8."
            ) from exc

    # ========================================================================
    # JSON DECODING
    # ========================================================================

    @classmethod
    def decode_json(
        cls,
        payload: bytes,
    ) -> dict[str, Any]:
        """
        Decode serialized JSON transaction bytes.

        The payload must contain a JSON object.
        """

        if not isinstance(payload, bytes):
            raise InvalidTransactionPayloadError(
                "Transaction payload must be bytes."
            )

        if not payload:
            raise InvalidTransactionPayloadError(
                "Transaction payload cannot be empty."
            )

        text = cls._decode_utf8(payload)

        try:
            decoded = json.loads(text)

        except json.JSONDecodeError as exc:
            raise InvalidTransactionPayloadError(
                "Transaction payload is not valid JSON."
            ) from exc

        if not isinstance(decoded, dict):
            raise InvalidTransactionPayloadError(
                "Transaction payload must decode to a JSON object."
            )

        return decoded

    # ========================================================================
    # CANONICALIZATION
    # ========================================================================

    @staticmethod
    def canonicalize(
        payload: Mapping[str, Any],
    ) -> bytes:
        """
        Convert a transaction mapping into deterministic JSON bytes.

        Canonicalization:

            - sorts object keys
            - uses compact separators
            - preserves Unicode characters
            - encodes as UTF-8

        The input mapping is never modified.
        """

        if not isinstance(payload, Mapping):
            raise InvalidTransactionPayloadError(
                "Transaction payload must be a mapping."
            )

        try:
            return json.dumps(
                dict(payload),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")

        except (TypeError, ValueError) as exc:
            raise InvalidTransactionPayloadError(
                "Transaction payload contains non-serializable values."
            ) from exc

    # ========================================================================
    # HASH
    # ========================================================================

    @staticmethod
    def payload_hash(
        payload: bytes,
    ) -> str:
        """
        Calculate the SHA-256 hash of the exact serialized application
        transaction payload.

        This is NOT a blockchain transaction hash.
        """

        if not isinstance(payload, bytes):
            raise InvalidTransactionPayloadError(
                "Payload must be bytes."
            )

        if not payload:
            raise InvalidTransactionPayloadError(
                "Payload cannot be empty."
            )

        return hashlib.sha256(payload).hexdigest()

    # ========================================================================
    # STRUCTURAL VALIDATION
    # ========================================================================

    @classmethod
    def validate_structure(
        cls,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Validate the generic transaction structure.

        This method does not mutate `payload`.

        It does not verify:

            - blockchain state
            - account balances
            - nonce state
            - signatures
            - blockchain-specific addresses
            - network-specific fee rules
            - network-specific serialization
        """

        if not isinstance(payload, Mapping):
            raise InvalidTransactionPayloadError(
                "Transaction must be a JSON object."
            )

        missing = cls.REQUIRED_FIELDS.difference(payload.keys())

        if missing:
            fields = ", ".join(sorted(missing))

            raise InvalidTransactionFieldError(
                f"Missing required transaction fields: {fields}"
            )

        cls.normalize_network(
            payload["network"]
        )

        cls.normalize_transaction_type(
            payload["transaction_type"]
        )

    # ========================================================================
    # DECODE
    # ========================================================================

    @classmethod
    def decode(
        cls,
        payload: bytes,
    ) -> DecodedTransaction:
        """
        Decode and structurally validate a serialized application payload.
        """

        decoded = cls.decode_json(payload)

        cls.validate_structure(decoded)

        network = cls.normalize_network(
            decoded["network"]
        )

        transaction_type = cls.normalize_transaction_type(
            decoded["transaction_type"]
        )

        return DecodedTransaction(
            network=network,
            transaction_type=transaction_type,
            payload=decoded,
            payload_hash=cls.payload_hash(payload),
        )

    # ========================================================================
    # DECODE CANONICAL PAYLOAD
    # ========================================================================

    @classmethod
    def decode_canonical(
        cls,
        payload: Mapping[str, Any],
    ) -> DecodedTransaction:
        """
        Canonicalize a transaction mapping and decode it.

        This is useful when TransactionBuilder produces a Python mapping.
        """

        serialized = cls.canonicalize(payload)

        return cls.decode(serialized)

    # ========================================================================
    # FIELD ACCESS
    # ========================================================================

    @staticmethod
    def get_field(
        transaction: DecodedTransaction,
        field: str,
        default: Any = None,
    ) -> Any:
        """
        Safely retrieve a field from a decoded transaction.
        """

        if not isinstance(
            transaction,
            DecodedTransaction,
        ):
            raise InvalidTransactionPayloadError(
                "transaction must be a DecodedTransaction."
            )

        if not isinstance(field, str):
            raise InvalidTransactionFieldError(
                "Field name must be a string."
            )

        if not field:
            raise InvalidTransactionFieldError(
                "Field name cannot be empty."
            )

        return transaction.payload.get(
            field,
            default,
        )

    # ========================================================================
    # SUMMARY
    # ========================================================================

    @classmethod
    def summary(
        cls,
        transaction: DecodedTransaction,
    ) -> dict[str, Any]:
        """
        Return a safe transaction summary for auditing/logging.

        Private keys, mnemonic material, signatures, and secret material
        are never extracted by this method.
        """

        if not isinstance(
            transaction,
            DecodedTransaction,
        ):
            raise InvalidTransactionPayloadError(
                "transaction must be a DecodedTransaction."
            )

        return {
            "network": transaction.network,
            "transaction_type": transaction.transaction_type,
            "payload_hash": transaction.payload_hash,
            "nonce": transaction.nonce,
            "from": transaction.sender,
            "to": transaction.recipient,
            "value": (
                str(transaction.value)
                if transaction.value is not None
                else None
            ),
            "chain_id": transaction.chain_id,
        }


__all__ = [
    "TransactionDecodeError",
    "InvalidTransactionPayloadError",
    "UnsupportedTransactionNetworkError",
    "InvalidTransactionFieldError",
    "DecodedTransaction",
    "TransactionDecoder",
]