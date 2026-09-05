"""
HappyWallet Transaction Broadcaster.

Security boundary
-----------------

This module is responsible ONLY for submitting an already-signed,
network-specific transaction to a blockchain provider.

Architecture
------------

    TransactionBuilder
            |
            v
    unsigned transaction
            |
            v
    Network TransactionEncoder
            |
            v
    signing digest / signing material
            |
            v
    SigningService
            |
            v
    fully serialized signed transaction
            |
            v
    TransactionBroadcaster
            |
            +---- EthereumBroadcaster
            |
            +---- BitcoinBroadcaster
            |
            +---- TronBroadcaster
            |
            v
    blockchain RPC


Security rules
--------------

This module MUST NOT:

    - access private keys
    - access mnemonic phrases
    - decrypt wallet secrets
    - sign transactions
    - build transactions
    - serialize unsigned transactions
    - modify transaction payloads
    - communicate with wallet/key storage
    - persist secrets
    - log raw signed transactions
    - expose RPC credentials

Important
---------

``raw_transaction`` means the exact, network-specific, fully signed
transaction bytes expected by the network broadcaster.

It is NOT:

    - an unsigned TransactionBuilder payload
    - an application JSON payload
    - a signing digest
    - a DER signature
    - a public key
    - an arbitrary ``payload`` attribute

The broadcaster does not attempt to understand or transform the
transaction bytes. Network-specific validation and RPC submission
belong to the network broadcaster implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping, Protocol


# ============================================================================
# EXCEPTIONS
# ============================================================================


class BroadcasterError(Exception):
    """Base exception for all transaction-broadcast failures."""


class UnsupportedNetworkError(BroadcasterError):
    """Raised when the requested blockchain network is unsupported."""


class InvalidSignedTransactionError(BroadcasterError):
    """
    Raised when signed transaction data is invalid.

    Exception messages intentionally never contain transaction bytes.
    """


class BroadcastConnectionError(BroadcasterError):
    """Raised when communication with a blockchain provider fails."""


class BroadcastRejectedError(BroadcasterError):
    """Raised when a blockchain provider rejects a transaction."""


class BroadcastResponseError(BroadcasterError):
    """
    Raised when a provider returns an unusable broadcast response.
    """


# ============================================================================
# DATA TYPES
# ============================================================================


@dataclass(frozen=True, slots=True)
class BroadcastRequest:
    """
    Immutable request containing an already-signed transaction.

    ``raw_transaction`` MUST be the exact serialized transaction bytes
    appropriate for the selected blockchain network.
    """

    network: str
    raw_transaction: bytes


@dataclass(frozen=True, slots=True)
class BroadcastResponse:
    """
    Stable application-level result of a successful broadcast.

    ``transaction_hash`` is the blockchain transaction identifier.

    It is deliberately distinct from:

        - TransactionBuilder payload hash
        - application transaction ID
        - signing digest

    Provider-specific response objects are not retained here.
    """

    network: str
    transaction_hash: str


class NetworkBroadcaster(Protocol):
    """
    Contract implemented by network-specific broadcasters.

    Implementations own:

        - provider communication
        - network-specific RPC
        - provider response handling
        - provider error translation
        - blockchain-specific transaction validation
    """

    def broadcast(
        self,
        *,
        raw_transaction: bytes,
    ) -> str:
        """
        Submit a fully serialized signed transaction.

        Returns the blockchain transaction hash.
        """
        ...


# ============================================================================
# TRANSACTION BROADCASTER
# ============================================================================


class TransactionBroadcaster:
    """
    Central transaction-broadcast orchestration boundary.

    Responsibilities
    ----------------

    1. Normalize the network.
    2. Validate the raw signed transaction container.
    3. Resolve the network-specific broadcaster.
    4. Submit the exact signed bytes.
    5. Validate the returned transaction hash.
    6. Return a stable BroadcastResponse.

    Deliberately excluded
    ---------------------

    - transaction construction
    - transaction serialization
    - transaction signing
    - private-key management
    - mnemonic management
    - wallet persistence
    - transaction-history indexing
    - generic payload handling
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

    # Defensive application-level limit.
    #
    # This is NOT a blockchain protocol limit.
    MAX_SIGNED_TRANSACTION_BYTES: Final[int] = 1_000_000

    # ========================================================================
    # NETWORK NORMALIZATION
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
            raise UnsupportedNetworkError(
                "Network must be a string."
            )

        normalized = network.strip().lower()

        if not normalized:
            raise UnsupportedNetworkError(
                "Network cannot be empty."
            )

        normalized = cls.NETWORK_ALIASES.get(
            normalized,
            normalized,
        )

        if normalized not in cls.SUPPORTED_NETWORKS:
            raise UnsupportedNetworkError(
                f"Unsupported network: {network}"
            )

        return normalized

    # ========================================================================
    # RAW TRANSACTION VALIDATION
    # ========================================================================

    @classmethod
    def validate_raw_transaction(
        cls,
        raw_transaction: bytes,
    ) -> bytes:
        """
        Validate the container holding a fully signed transaction.

        This method intentionally does NOT attempt to interpret the
        transaction. Network-specific validation belongs to the adapter.
        """

        if not isinstance(raw_transaction, bytes):
            raise InvalidSignedTransactionError(
                "Signed transaction must be bytes."
            )

        if not raw_transaction:
            raise InvalidSignedTransactionError(
                "Signed transaction cannot be empty."
            )

        if len(raw_transaction) > cls.MAX_SIGNED_TRANSACTION_BYTES:
            raise InvalidSignedTransactionError(
                "Signed transaction exceeds the maximum allowed size."
            )

        return raw_transaction

    # ========================================================================
    # REQUEST VALIDATION
    # ========================================================================

    @classmethod
    def validate_request(
        cls,
        request: BroadcastRequest,
    ) -> BroadcastRequest:
        """
        Validate and normalize a broadcast request.
        """

        if not isinstance(request, BroadcastRequest):
            raise InvalidSignedTransactionError(
                "Invalid broadcast request."
            )

        network = cls.normalize_network(
            request.network
        )

        raw_transaction = cls.validate_raw_transaction(
            request.raw_transaction
        )

        return BroadcastRequest(
            network=network,
            raw_transaction=raw_transaction,
        )

    # ========================================================================
    # PUBLIC BROADCAST API
    # ========================================================================

    @classmethod
    def broadcast(
        cls,
        *,
        network: str,
        raw_transaction: bytes,
    ) -> BroadcastResponse:
        """
        Broadcast a fully serialized signed transaction.

        Parameters
        ----------
        network:
            Blockchain network identifier.

        raw_transaction:
            Exact serialized signed transaction bytes.

        Returns
        -------
        BroadcastResponse
            Stable normalized broadcast result.

        Raises
        ------
        UnsupportedNetworkError
            If the network is unsupported.

        InvalidSignedTransactionError
            If the supplied transaction bytes are invalid.

        BroadcastConnectionError
            If provider communication fails.

        BroadcastRejectedError
            If the provider rejects the transaction.

        BroadcastResponseError
            If the provider does not return a usable transaction hash.

        Important
        ---------

        This method intentionally accepts ONLY ``bytes``.

        It does not accept:

            - UnsignedTransaction
            - SignedTransaction objects
            - ``payload`` attributes
            - signature objects
            - dictionaries
            - hexadecimal strings
        """

        request = cls.validate_request(
            BroadcastRequest(
                network=network,
                raw_transaction=raw_transaction,
            )
        )

        broadcaster = cls._get_network_broadcaster(
            request.network
        )

        try:
            transaction_hash = broadcaster.broadcast(
                raw_transaction=request.raw_transaction,
            )

        except BroadcastRejectedError:
            raise

        except BroadcastConnectionError:
            raise

        except BroadcastResponseError:
            raise

        except BroadcasterError:
            raise

        except Exception as exc:
            raise BroadcastConnectionError(
                f"Failed to broadcast transaction on "
                f"{request.network}."
            ) from exc

        normalized_hash = cls._normalize_transaction_hash(
            transaction_hash
        )

        return BroadcastResponse(
            network=request.network,
            transaction_hash=normalized_hash,
        )

    # ========================================================================
    # NETWORK RESOLUTION
    # ========================================================================

    @classmethod
    def _get_network_broadcaster(
        cls,
        network: str,
    ) -> NetworkBroadcaster:
        """
        Resolve the network-specific broadcaster lazily.

        Lazy imports prevent optional blockchain dependencies from being
        required during application startup.
        """

        if network == "ethereum":
            from apps.transaction.services.networks.ethereum import (
                EthereumBroadcaster,
            )

            return EthereumBroadcaster()

        if network == "bitcoin":
            from apps.transaction.services.networks.bitcoin import (
                BitcoinBroadcaster,
            )

            return BitcoinBroadcaster()

        if network == "tron":
            from apps.transaction.services.networks.tron import (
                TronBroadcaster,
            )

            return TronBroadcaster()

        # This should normally be unreachable because network normalization
        # occurs before broadcaster resolution.
        raise UnsupportedNetworkError(
            f"No broadcaster configured for {network}."
        )

    # ========================================================================
    # TRANSACTION HASH NORMALIZATION
    # ========================================================================

    @staticmethod
    def _normalize_transaction_hash(
        transaction_hash: object,
    ) -> str:
        """
        Normalize a blockchain transaction hash.

        The network-specific broadcaster is responsible for extracting
        the hash from its provider response.

        The central broadcaster only requires the final result to be a
        non-empty string.
        """

        if not isinstance(transaction_hash, str):
            raise BroadcastResponseError(
                "Blockchain broadcaster returned an invalid "
                "transaction hash."
            )

        normalized = transaction_hash.strip()

        if not normalized:
            raise BroadcastResponseError(
                "Blockchain broadcaster returned an empty "
                "transaction hash."
            )

        return normalized
