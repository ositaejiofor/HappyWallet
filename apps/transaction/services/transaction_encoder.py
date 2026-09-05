"""
HappyWallet Transaction Encoder.

Final serialization boundary between cryptographic signing and
transaction broadcasting.

Architecture
------------

    TransactionBuilder
            |
            v
    canonical unsigned payload
            |
            v
      SigningService
            |
            v
     cryptographic signature
            |
            v
    TransactionEncoder
            |
            v
    network-specific serializer
            |
            v
      signed transaction
            |
            v
    TransactionBroadcaster
            |
            v
       Blockchain RPC

Security boundary
-----------------

This module MUST NOT:

- access private keys
- access mnemonic phrases
- sign transactions
- communicate with blockchain RPC endpoints
- persist transaction secrets
- construct signatures
- modify wallet secrets

The encoder only combines an already-built unsigned transaction with
an already-created cryptographic signature and delegates the final
network-specific encoding to a dedicated serializer.

Supported networks:

- Ethereum
- Bitcoin
- Tron
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Mapping, Protocol


# ============================================================================
# EXCEPTIONS
# ============================================================================


class TransactionEncoderError(Exception):
    """Base exception for transaction-encoder failures."""


class UnsupportedEncodingNetworkError(TransactionEncoderError):
    """Raised when no serializer exists for the requested network."""


class InvalidEncodingInputError(TransactionEncoderError):
    """Raised when encoder input is invalid."""


class TransactionSerializationError(TransactionEncoderError):
    """Raised when network-specific serialization fails."""


# ============================================================================
# RESULT TYPE
# ============================================================================


@dataclass(frozen=True)
class EncodedTransaction:
    """
    Final signed transaction ready for the broadcaster.

    ``raw_transaction`` contains the exact bytes that should be submitted
    to the blockchain network.

    No private-key material is contained in this object.
    """

    network: str
    raw_transaction: bytes
    transaction_hash: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


# ============================================================================
# SERIALIZER PROTOCOL
# ============================================================================


class NetworkTransactionSerializer(Protocol):
    """
    Protocol implemented by network-specific serializers.

    Serializers are responsible for converting the unsigned transaction
    and cryptographic signature into the exact signed wire format required
    by the target blockchain.
    """

    def encode(
        self,
        *,
        payload: bytes,
        signature_der: bytes,
        public_key: bytes,
        metadata: Mapping[str, Any],
    ) -> bytes | EncodedTransaction | Mapping[str, Any]:
        """Encode a signed transaction."""


# ============================================================================
# TRANSACTION ENCODER
# ============================================================================


class TransactionEncoder:
    """
    Dispatch final signed-transaction encoding to network serializers.

    This class intentionally contains no blockchain-specific serialization
    logic itself.
    """

    SUPPORTED_NETWORKS: Final[frozenset[str]] = frozenset(
        {
            "ethereum",
            "bitcoin",
            "tron",
        }
    )

    NETWORK_ALIASES: Final[Mapping[str, str]] = {
        "eth": "ethereum",
        "ethereum-mainnet": "ethereum",
        "ethereum_testnet": "ethereum",
        "btc": "bitcoin",
        "bitcoin-mainnet": "bitcoin",
        "bitcoin_testnet": "bitcoin",
        "trx": "tron",
        "tron-mainnet": "tron",
    }

    MAX_RAW_TRANSACTION_BYTES: Final[int] = 128 * 1024

    _serializers: dict[str, NetworkTransactionSerializer] = {}

    # ------------------------------------------------------------------------
    # NETWORK
    # ------------------------------------------------------------------------

    @classmethod
    def normalize_network(cls, network: str) -> str:
        """Normalize a supported network identifier."""

        if not isinstance(network, str):
            raise UnsupportedEncodingNetworkError(
                "Network must be a string."
            )

        normalized = network.strip().lower()

        normalized = cls.NETWORK_ALIASES.get(
            normalized,
            normalized,
        )

        if normalized not in cls.SUPPORTED_NETWORKS:
            raise UnsupportedEncodingNetworkError(
                f"Unsupported transaction encoding network: {network}"
            )

        return normalized

    # ------------------------------------------------------------------------
    # SERIALIZER REGISTRATION
    # ------------------------------------------------------------------------

    @classmethod
    def register_serializer(
        cls,
        network: str,
        serializer: NetworkTransactionSerializer,
    ) -> None:
        """
        Register a network-specific serializer.

        Registration is explicit so the generic encoder never silently
        falls back to an incorrect wire format.
        """

        normalized = cls.normalize_network(network)

        if serializer is None:
            raise InvalidEncodingInputError(
                "Serializer cannot be None."
            )

        encode_method = getattr(
            serializer,
            "encode",
            None,
        )

        if not callable(encode_method):
            raise InvalidEncodingInputError(
                "Serializer must provide an encode() method."
            )

        cls._serializers[normalized] = serializer

    @classmethod
    def unregister_serializer(
        cls,
        network: str,
    ) -> None:
        """Remove a registered serializer."""

        normalized = cls.normalize_network(network)

        cls._serializers.pop(
            normalized,
            None,
        )

    @classmethod
    def get_serializer(
        cls,
        network: str,
    ) -> NetworkTransactionSerializer:
        """Return the serializer registered for a network."""

        normalized = cls.normalize_network(network)

        serializer = cls._serializers.get(
            normalized
        )

        if serializer is None:
            raise UnsupportedEncodingNetworkError(
                "No transaction serializer registered for network: "
                f"{normalized}"
            )

        return serializer

    # ------------------------------------------------------------------------
    # INPUT VALIDATION
    # ------------------------------------------------------------------------

    @staticmethod
    def _validate_bytes(
        value: bytes,
        *,
        field_name: str,
    ) -> bytes:
        """Validate a required byte sequence."""

        if not isinstance(value, bytes):
            raise InvalidEncodingInputError(
                f"{field_name} must be bytes."
            )

        if not value:
            raise InvalidEncodingInputError(
                f"{field_name} cannot be empty."
            )

        return value

    @classmethod
    def _validate_raw_transaction(
        cls,
        raw_transaction: bytes,
    ) -> bytes:
        """Validate final signed transaction bytes."""

        cls._validate_bytes(
            raw_transaction,
            field_name="Raw signed transaction",
        )

        if len(raw_transaction) > cls.MAX_RAW_TRANSACTION_BYTES:
            raise InvalidEncodingInputError(
                "Raw signed transaction is too large."
            )

        return raw_transaction

    # ------------------------------------------------------------------------
    # RESULT NORMALIZATION
    # ------------------------------------------------------------------------

    @classmethod
    def _normalize_result(
        cls,
        *,
        network: str,
        result: bytes | EncodedTransaction | Mapping[str, Any],
    ) -> EncodedTransaction:
        """Normalize serializer output into EncodedTransaction."""

        if isinstance(result, bytes):
            return EncodedTransaction(
                network=network,
                raw_transaction=cls._validate_raw_transaction(
                    result
                ),
                transaction_hash=None,
                metadata={},
            )

        if isinstance(result, EncodedTransaction):
            if result.network != network:
                raise TransactionSerializationError(
                    "Serializer returned the wrong network."
                )

            return EncodedTransaction(
                network=network,
                raw_transaction=cls._validate_raw_transaction(
                    result.raw_transaction
                ),
                transaction_hash=result.transaction_hash,
                metadata=dict(result.metadata or {}),
            )

        if isinstance(result, Mapping):
            raw_transaction = result.get(
                "raw_transaction"
            )

            if raw_transaction is None:
                raw_transaction = result.get(
                    "raw"
                )

            if raw_transaction is None:
                raise TransactionSerializationError(
                    "Serializer did not return raw transaction bytes."
                )

            if not isinstance(raw_transaction, bytes):
                raise TransactionSerializationError(
                    "Serializer returned invalid raw transaction data."
                )

            transaction_hash = result.get(
                "transaction_hash"
            )

            if transaction_hash is not None:
                transaction_hash = str(
                    transaction_hash
                )

            metadata = result.get(
                "metadata"
            ) or {}

            if not isinstance(metadata, Mapping):
                raise TransactionSerializationError(
                    "Serializer metadata must be a mapping."
                )

            return EncodedTransaction(
                network=network,
                raw_transaction=cls._validate_raw_transaction(
                    raw_transaction
                ),
                transaction_hash=transaction_hash,
                metadata=dict(metadata),
            )

        raise TransactionSerializationError(
            "Serializer returned an unsupported result."
        )

    # ------------------------------------------------------------------------
    # ENCODE
    # ------------------------------------------------------------------------

    @classmethod
    def encode(
        cls,
        *,
        network: str,
        payload: bytes,
        signature_der: bytes,
        public_key: bytes,
        metadata: Mapping[str, Any] | None = None,
    ) -> EncodedTransaction:
        """
        Encode a signed transaction.

        This method does not sign anything.

        ``payload`` is the exact unsigned transaction payload.

        ``signature_der`` is an already-created cryptographic signature.

        ``public_key`` corresponds to the signing key.

        ``metadata`` contains non-secret information required by the
        network-specific serializer.
        """

        normalized_network = cls.normalize_network(
            network
        )

        cls._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        cls._validate_bytes(
            signature_der,
            field_name="Signature",
        )

        cls._validate_bytes(
            public_key,
            field_name="Public key",
        )

        if metadata is None:
            normalized_metadata: Mapping[str, Any] = {}
        elif isinstance(metadata, Mapping):
            normalized_metadata = dict(metadata)
        else:
            raise InvalidEncodingInputError(
                "Transaction metadata must be a mapping."
            )

        serializer = cls.get_serializer(
            normalized_network
        )

        try:
            result = serializer.encode(
                payload=payload,
                signature_der=signature_der,
                public_key=public_key,
                metadata=normalized_metadata,
            )

        except TransactionEncoderError:
            raise

        except Exception as exc:
            raise TransactionSerializationError(
                "Network-specific transaction serialization failed."
            ) from exc

        return cls._normalize_result(
            network=normalized_network,
            result=result,
        )

    # ------------------------------------------------------------------------
    # SERIALIZER DISCOVERY
    # ------------------------------------------------------------------------

    @classmethod
    def is_registered(
        cls,
        network: str,
    ) -> bool:
        """Return whether a serializer is registered."""

        normalized = cls.normalize_network(
            network
        )

        return normalized in cls._serializers

    @classmethod
    def registered_networks(
        cls,
    ) -> tuple[str, ...]:
        """Return registered network names."""

        return tuple(
            sorted(
                cls._serializers.keys()
            )
        )


__all__ = [
    "EncodedTransaction",
    "InvalidEncodingInputError",
    "NetworkTransactionSerializer",
    "TransactionEncoder",
    "TransactionEncoderError",
    "TransactionSerializationError",
    "UnsupportedEncodingNetworkError",
]
