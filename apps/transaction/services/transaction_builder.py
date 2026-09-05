"""
HappyWallet Transaction Builder.

Application-layer construction and validation of unsigned transactions.

Architecture
------------

    Wallet / UI
         |
         v
    TransactionBuilder
         |
         | normalized unsigned transaction
         v
    TransactionEncoder
         |
         | network-specific signing preimage
         v
    SigningService
         |
         | cryptographic signature
         v
    TransactionEncoder
         |
         | blockchain-ready signed bytes
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
- broadcast transactions
- communicate with blockchain RPC endpoints
- persist secrets
- log private transaction material

The builder is deliberately blockchain-agnostic.

IMPORTANT
---------

The payload produced by this module is an APPLICATION-LEVEL canonical
representation.

It is NOT:

- Ethereum RLP
- Ethereum EIP-2718 serialization
- Bitcoin transaction serialization
- Bitcoin PSBT
- Tron protobuf serialization

Real blockchain serialization belongs to TransactionEncoder and its
network-specific implementations.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Final, Mapping

from django.core.exceptions import ValidationError


# ============================================================================
# EXCEPTIONS
# ============================================================================


class TransactionBuilderError(Exception):
    """Base exception for transaction-builder failures."""


class InvalidTransactionError(TransactionBuilderError):
    """Raised when generic transaction data is invalid."""


class UnsupportedTransactionNetworkError(TransactionBuilderError):
    """Raised when the requested network is unsupported."""


class InvalidTransactionAmountError(TransactionBuilderError):
    """Raised when a transaction amount is invalid."""


class InvalidTransactionAddressError(TransactionBuilderError):
    """Raised when an address is invalid."""


# ============================================================================
# DATA TYPES
# ============================================================================


@dataclass(frozen=True, slots=True)
class TransactionRequest:
    """
    High-level unsigned transaction request.

    This object contains no signing material.
    """

    network: str
    asset: str
    sender: str
    recipient: str
    amount: Decimal | str | int

    nonce: int | None = None

    # EVM-style fee fields.
    gas_limit: int | None = None
    gas_price: int | None = None
    max_fee_per_gas: int | None = None
    max_priority_fee_per_gas: int | None = None

    # UTXO-style fee metadata.
    fee_rate: int | None = None

    # Token metadata.
    token_contract: str | None = None
    token_standard: str | None = None
    decimals: int | None = None

    # Application-level reference.
    reference: str | None = None

    # Additional application/network metadata.
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UnsignedTransaction:
    """
    Canonical unsigned application transaction.

    `payload` is deterministic application-level serialization.

    It MUST NOT be treated as blockchain wire-format bytes.
    """

    transaction_id: str
    network: str
    asset: str

    sender: str
    recipient: str
    amount: str

    nonce: int | None

    gas_limit: int | None
    gas_price: int | None
    max_fee_per_gas: int | None
    max_priority_fee_per_gas: int | None

    fee_rate: int | None

    token_contract: str | None
    token_standard: str | None
    decimals: int | None

    reference: str | None

    payload: bytes
    payload_hash: str

    metadata: Mapping[str, Any]


# ============================================================================
# TRANSACTION BUILDER
# ============================================================================


class TransactionBuilder:
    """
    Construct and validate canonical unsigned transactions.

    Responsibilities
    ----------------

    1. Normalize network identifiers.
    2. Normalize generic transaction fields.
    3. Validate generic transaction invariants.
    4. Produce deterministic application-level serialization.
    5. Generate an application transaction identifier.

    Non-responsibilities
    --------------------

    The builder does NOT:

    - fetch blockchain state
    - determine the current nonce
    - estimate gas
    - validate balances
    - validate signatures
    - sign
    - encode Ethereum RLP
    - encode Bitcoin transactions
    - encode Tron protobuf
    - broadcast transactions
    """

    # ------------------------------------------------------------------------
    # NETWORKS
    # ------------------------------------------------------------------------

    SUPPORTED_NETWORKS: Final[frozenset[str]] = frozenset(
        {
            "ethereum",
            "bitcoin",
            "tron",
        }
    )

    NETWORK_ALIASES: Final[dict[str, str]] = {
        "eth": "ethereum",
        "ethereum-mainnet": "ethereum",
        "ethereum_testnet": "ethereum",
        "ethereum-testnet": "ethereum",

        "btc": "bitcoin",
        "bitcoin-mainnet": "bitcoin",
        "bitcoin_testnet": "bitcoin",
        "bitcoin-testnet": "bitcoin",

        "trx": "tron",
        "tron-mainnet": "tron",
        "tron_testnet": "tron",
        "tron-testnet": "tron",
    }

    # ------------------------------------------------------------------------
    # LIMITS
    # ------------------------------------------------------------------------

    MAX_ASSET_LENGTH: Final[int] = 20
    MAX_ADDRESS_LENGTH: Final[int] = 255
    MAX_REFERENCE_LENGTH: Final[int] = 100
    MAX_DECIMALS: Final[int] = 36

    # Prevent arbitrarily large application payloads from entering the
    # canonical serialization boundary.
    MAX_METADATA_KEYS: Final[int] = 100
    MAX_METADATA_DEPTH: Final[int] = 8

    # ------------------------------------------------------------------------
    # TOKEN STANDARDS
    # ------------------------------------------------------------------------

    TOKEN_STANDARD_ALIASES: Final[dict[str, str]] = {
        "erc-20": "erc20",
        "erc_20": "erc20",
        "trc-20": "trc20",
        "trc_20": "trc20",
        "bep-20": "bep20",
        "bep_20": "bep20",
    }

    SUPPORTED_TOKEN_STANDARDS: Final[frozenset[str]] = frozenset(
        {
            "native",
            "erc20",
            "trc20",
            "bep20",
            "spl",
        }
    )

    # ------------------------------------------------------------------------
    # NETWORK
    # ------------------------------------------------------------------------

    @classmethod
    def normalize_network(cls, network: str) -> str:
        """
        Normalize a blockchain network identifier.
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

    # ------------------------------------------------------------------------
    # ASSET
    # ------------------------------------------------------------------------

    @classmethod
    def normalize_asset(cls, asset: str) -> str:
        """
        Normalize an application asset identifier.

        Examples:

            ETH
            BTC
            TRX
            USDT
        """

        if not isinstance(asset, str):
            raise InvalidTransactionError(
                "Asset must be a string."
            )

        normalized = asset.strip().upper()

        if not normalized:
            raise InvalidTransactionError(
                "Asset cannot be empty."
            )

        if len(normalized) > cls.MAX_ASSET_LENGTH:
            raise InvalidTransactionError(
                "Asset symbol is too long."
            )

        if not re.fullmatch(
            r"[A-Z0-9._-]+",
            normalized,
        ):
            raise InvalidTransactionError(
                "Asset contains invalid characters."
            )

        return normalized

    # ------------------------------------------------------------------------
    # AMOUNT
    # ------------------------------------------------------------------------

    @staticmethod
    def normalize_amount(
        amount: Decimal | str | int,
    ) -> Decimal:
        """
        Normalize a transaction amount.

        Floating-point values are deliberately not accepted.

        Monetary/asset quantities must enter the builder as:

            Decimal
            string
            integer
        """

        if isinstance(amount, bool):
            raise InvalidTransactionAmountError(
                "Transaction amount must not be boolean."
            )

        if isinstance(amount, float):
            raise InvalidTransactionAmountError(
                "Transaction amount must not be a float."
            )

        try:
            normalized = Decimal(str(amount))

        except (InvalidOperation, ValueError, TypeError) as exc:
            raise InvalidTransactionAmountError(
                "Invalid transaction amount."
            ) from exc

        if not normalized.is_finite():
            raise InvalidTransactionAmountError(
                "Transaction amount must be finite."
            )

        if normalized <= Decimal("0"):
            raise InvalidTransactionAmountError(
                "Transaction amount must be greater than zero."
            )

        return normalized

    # ------------------------------------------------------------------------
    # ADDRESS
    # ------------------------------------------------------------------------

    @classmethod
    def normalize_address(
        cls,
        address: str,
        *,
        field_name: str,
    ) -> str:
        """
        Perform generic address validation.

        Blockchain-specific address validation belongs to the appropriate
        network implementation.

        This method intentionally does NOT attempt to determine whether an
        address is a valid Ethereum, Bitcoin, or Tron address.
        """

        if not isinstance(address, str):
            raise InvalidTransactionAddressError(
                f"{field_name} must be a string."
            )

        normalized = address.strip()

        if not normalized:
            raise InvalidTransactionAddressError(
                f"{field_name} cannot be empty."
            )

        if len(normalized) > cls.MAX_ADDRESS_LENGTH:
            raise InvalidTransactionAddressError(
                f"{field_name} is too long."
            )

        return normalized

    # ------------------------------------------------------------------------
    # NONCE
    # ------------------------------------------------------------------------

    @staticmethod
    def validate_nonce(
        nonce: int | None,
    ) -> int | None:
        """
        Validate an optional transaction nonce.

        The builder validates shape only.

        It does NOT determine whether the nonce is currently valid on-chain.
        """

        if nonce is None:
            return None

        if isinstance(nonce, bool):
            raise InvalidTransactionError(
                "Nonce must be an integer."
            )

        if not isinstance(nonce, int):
            raise InvalidTransactionError(
                "Nonce must be an integer."
            )

        if nonce < 0:
            raise InvalidTransactionError(
                "Nonce cannot be negative."
            )

        return nonce

    # ------------------------------------------------------------------------
    # POSITIVE INTEGER
    # ------------------------------------------------------------------------

    @staticmethod
    def validate_positive_integer(
        value: int | None,
        *,
        field_name: str,
    ) -> int | None:
        """
        Validate an optional non-negative integer.

        Zero is accepted because some network-specific transaction fields
        legitimately permit zero.
        """

        if value is None:
            return None

        if isinstance(value, bool):
            raise InvalidTransactionError(
                f"{field_name} must be an integer."
            )

        if not isinstance(value, int):
            raise InvalidTransactionError(
                f"{field_name} must be an integer."
            )

        if value < 0:
            raise InvalidTransactionError(
                f"{field_name} cannot be negative."
            )

        return value

    # ------------------------------------------------------------------------
    # TOKEN STANDARD
    # ------------------------------------------------------------------------

    @classmethod
    def normalize_token_standard(
        cls,
        token_standard: str | None,
    ) -> str | None:
        """
        Normalize a token standard identifier.
        """

        if token_standard is None:
            return None

        if not isinstance(token_standard, str):
            raise InvalidTransactionError(
                "Token standard must be a string."
            )

        normalized = token_standard.strip().lower()

        if not normalized:
            return None

        normalized = cls.TOKEN_STANDARD_ALIASES.get(
            normalized,
            normalized,
        )

        if normalized not in cls.SUPPORTED_TOKEN_STANDARDS:
            raise InvalidTransactionError(
                f"Unsupported token standard: {token_standard}"
            )

        return normalized

    # ------------------------------------------------------------------------
    # DECIMALS
    # ------------------------------------------------------------------------

    @classmethod
    def validate_decimals(
        cls,
        decimals: int | None,
    ) -> int | None:
        """
        Validate token decimal precision.

        This is generic validation only. Actual network/token contract
        decimals must be verified by the network/token layer where required.
        """

        if decimals is None:
            return None

        if isinstance(decimals, bool):
            raise InvalidTransactionError(
                "Decimals must be an integer."
            )

        if not isinstance(decimals, int):
            raise InvalidTransactionError(
                "Decimals must be an integer."
            )

        if not 0 <= decimals <= cls.MAX_DECIMALS:
            raise InvalidTransactionError(
                f"Decimals must be between 0 and {cls.MAX_DECIMALS}."
            )

        return decimals

    # ------------------------------------------------------------------------
    # REFERENCE
    # ------------------------------------------------------------------------

    @classmethod
    def normalize_reference(
        cls,
        reference: str | None,
    ) -> str | None:
        """
        Normalize an application-level transaction reference.
        """

        if reference is None:
            return None

        if not isinstance(reference, str):
            raise InvalidTransactionError(
                "Transaction reference must be a string."
            )

        normalized = reference.strip()

        if not normalized:
            return None

        if len(normalized) > cls.MAX_REFERENCE_LENGTH:
            raise InvalidTransactionError(
                "Transaction reference is too long."
            )

        return normalized

    # =========================================================================
    # METADATA VALIDATION
    # =========================================================================

    @classmethod
    def _validate_metadata_value(
        cls,
        value: Any,
        *,
        depth: int = 0,
    ) -> None:
        """
        Validate that metadata can safely participate in canonical JSON.

        Supported values are deliberately limited to JSON-compatible types.
        """

        if depth > cls.MAX_METADATA_DEPTH:
            raise InvalidTransactionError(
                "Transaction metadata nesting is too deep."
            )

        if value is None:
            return

        if isinstance(value, (str, int, bool)):
            return

        if isinstance(value, float):
            raise InvalidTransactionError(
                "Transaction metadata must not contain floats."
            )

        if isinstance(value, Decimal):
            return

        if isinstance(value, Mapping):
            if len(value) > cls.MAX_METADATA_KEYS:
                raise InvalidTransactionError(
                    "Transaction metadata contains too many keys."
                )

            for key, item in value.items():
                if not isinstance(key, str):
                    raise InvalidTransactionError(
                        "Transaction metadata keys must be strings."
                    )

                cls._validate_metadata_value(
                    item,
                    depth=depth + 1,
                )

            return

        if isinstance(value, (list, tuple)):
            for item in value:
                cls._validate_metadata_value(
                    item,
                    depth=depth + 1,
                )

            return

        raise InvalidTransactionError(
            "Transaction metadata contains unsupported values."
        )

    @classmethod
    def normalize_metadata(
        cls,
        metadata: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Normalize and validate application metadata.
        """

        if metadata is None:
            return {}

        if not isinstance(metadata, Mapping):
            raise InvalidTransactionError(
                "Transaction metadata must be a mapping."
            )

        if len(metadata) > cls.MAX_METADATA_KEYS:
            raise InvalidTransactionError(
                "Transaction metadata contains too many keys."
            )

        normalized: dict[str, Any] = {}

        for key, value in metadata.items():
            if not isinstance(key, str):
                raise InvalidTransactionError(
                    "Transaction metadata keys must be strings."
                )

            normalized[key] = cls._normalize_metadata_value(
                value
            )

        return normalized

    @classmethod
    def _normalize_metadata_value(
        cls,
        value: Any,
        *,
        depth: int = 0,
    ) -> Any:
        """
        Recursively normalize metadata into deterministic JSON-compatible
        Python values.
        """

        if depth > cls.MAX_METADATA_DEPTH:
            raise InvalidTransactionError(
                "Transaction metadata nesting is too deep."
            )

        if value is None:
            return None

        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            return value

        if isinstance(value, int):
            return value

        if isinstance(value, float):
            raise InvalidTransactionError(
                "Transaction metadata must not contain floats."
            )

        if isinstance(value, Decimal):
            return format(value, "f")

        if isinstance(value, Mapping):
            if len(value) > cls.MAX_METADATA_KEYS:
                raise InvalidTransactionError(
                    "Transaction metadata contains too many keys."
                )

            result: dict[str, Any] = {}

            for key, item in value.items():
                if not isinstance(key, str):
                    raise InvalidTransactionError(
                        "Transaction metadata keys must be strings."
                    )

                result[key] = cls._normalize_metadata_value(
                    item,
                    depth=depth + 1,
                )

            return result

        if isinstance(value, (list, tuple)):
            return [
                cls._normalize_metadata_value(
                    item,
                    depth=depth + 1,
                )
                for item in value
            ]

        raise InvalidTransactionError(
            "Transaction metadata contains unsupported values."
        )

    # =========================================================================
    # REQUEST VALIDATION
    # =========================================================================

    @classmethod
    def validate_request(
        cls,
        request: TransactionRequest,
    ) -> TransactionRequest:
        """
        Validate and normalize a transaction request.
        """

        if not isinstance(request, TransactionRequest):
            raise InvalidTransactionError(
                "request must be a TransactionRequest."
            )

        network = cls.normalize_network(
            request.network
        )

        asset = cls.normalize_asset(
            request.asset
        )

        sender = cls.normalize_address(
            request.sender,
            field_name="Sender address",
        )

        recipient = cls.normalize_address(
            request.recipient,
            field_name="Recipient address",
        )

        if sender == recipient:
            raise InvalidTransactionError(
                "Sender and recipient cannot be identical."
            )

        amount = cls.normalize_amount(
            request.amount
        )

        nonce = cls.validate_nonce(
            request.nonce
        )

        gas_limit = cls.validate_positive_integer(
            request.gas_limit,
            field_name="Gas limit",
        )

        gas_price = cls.validate_positive_integer(
            request.gas_price,
            field_name="Gas price",
        )

        max_fee_per_gas = cls.validate_positive_integer(
            request.max_fee_per_gas,
            field_name="Max fee per gas",
        )

        max_priority_fee_per_gas = cls.validate_positive_integer(
            request.max_priority_fee_per_gas,
            field_name="Max priority fee per gas",
        )

        fee_rate = cls.validate_positive_integer(
            request.fee_rate,
            field_name="Fee rate",
        )

        decimals = cls.validate_decimals(
            request.decimals
        )

        token_standard = cls.normalize_token_standard(
            request.token_standard
        )

        token_contract = None

        if request.token_contract is not None:
            if not isinstance(request.token_contract, str):
                raise InvalidTransactionError(
                    "Token contract must be a string."
                )

            if request.token_contract.strip():
                token_contract = cls.normalize_address(
                    request.token_contract,
                    field_name="Token contract",
                )

        reference = cls.normalize_reference(
            request.reference
        )

        metadata = cls.normalize_metadata(
            request.metadata
        )

        # Generic invariant:
        #
        # A token contract without a token standard is ambiguous.
        if token_contract is not None and token_standard is None:
            raise InvalidTransactionError(
                "Token standard is required when token contract is supplied."
            )

        # Generic invariant:
        #
        # Native assets should not require a token contract.
        if token_standard == "native" and token_contract is not None:
            raise InvalidTransactionError(
                "Native transactions cannot specify a token contract."
            )

        return TransactionRequest(
            network=network,
            asset=asset,
            sender=sender,
            recipient=recipient,
            amount=amount,
            nonce=nonce,
            gas_limit=gas_limit,
            gas_price=gas_price,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            fee_rate=fee_rate,
            token_contract=token_contract,
            token_standard=token_standard,
            decimals=decimals,
            reference=reference,
            metadata=metadata,
        )

    # =========================================================================
    # TRANSACTION ID
    # =========================================================================

    @staticmethod
    def generate_transaction_id() -> str:
        """
        Generate an application-level transaction identifier.

        This is deliberately NOT the blockchain transaction hash.
        """

        return str(uuid.uuid4())

    # =========================================================================
    # CANONICALIZATION
    # =========================================================================

    @classmethod
    def _canonicalize(
        cls,
        value: Any,
    ) -> Any:
        """
        Convert supported values into deterministic JSON-compatible values.
        """

        if value is None:
            return None

        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            return value

        if isinstance(value, int):
            return value

        if isinstance(value, Decimal):
            return format(value, "f")

        if isinstance(value, Mapping):
            return {
                str(key): cls._canonicalize(item)
                for key, item in sorted(
                    value.items(),
                    key=lambda pair: str(pair[0]),
                )
            }

        if isinstance(value, (list, tuple)):
            return [
                cls._canonicalize(item)
                for item in value
            ]

        raise InvalidTransactionError(
            "Transaction contains a non-serializable value."
        )

    # =========================================================================
    # SERIALIZATION
    # =========================================================================

    @classmethod
    def serialize_request(
        cls,
        request: TransactionRequest,
    ) -> bytes:
        """
        Serialize a normalized transaction request deterministically.

        This is application-level canonical JSON.

        It is NOT blockchain wire-format serialization.
        """

        if not isinstance(request, TransactionRequest):
            raise InvalidTransactionError(
                "request must be a TransactionRequest."
            )

        normalized = cls.validate_request(
            request
        )

        data = {
            "amount": normalized.amount,
            "asset": normalized.asset,
            "decimals": normalized.decimals,
            "fee_rate": normalized.fee_rate,
            "gas_limit": normalized.gas_limit,
            "gas_price": normalized.gas_price,
            "max_fee_per_gas": normalized.max_fee_per_gas,
            "max_priority_fee_per_gas": (
                normalized.max_priority_fee_per_gas
            ),
            "metadata": normalized.metadata,
            "network": normalized.network,
            "nonce": normalized.nonce,
            "recipient": normalized.recipient,
            "reference": normalized.reference,
            "sender": normalized.sender,
            "token_contract": normalized.token_contract,
            "token_standard": normalized.token_standard,
        }

        canonical = cls._canonicalize(
            data
        )

        try:
            return json.dumps(
                canonical,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")

        except (TypeError, ValueError) as exc:
            raise InvalidTransactionError(
                "Transaction could not be canonically serialized."
            ) from exc

    # =========================================================================
    # PAYLOAD HASH
    # =========================================================================

    @staticmethod
    def payload_hash(
        payload: bytes,
    ) -> str:
        """
        Calculate SHA-256 over the exact application payload.

        This is NOT the blockchain transaction hash.
        """

        if not isinstance(payload, bytes):
            raise InvalidTransactionError(
                "Payload must be bytes."
            )

        if not payload:
            raise InvalidTransactionError(
                "Payload cannot be empty."
            )

        return hashlib.sha256(
            payload
        ).hexdigest()

    # =========================================================================
    # BUILD
    # =========================================================================

    @classmethod
    def build(
        cls,
        request: TransactionRequest,
    ) -> UnsignedTransaction:
        """
        Validate and construct an immutable unsigned transaction.

        No private-key operation occurs here.
        """

        normalized = cls.validate_request(
            request
        )

        payload = cls.serialize_request(
            normalized
        )

        return UnsignedTransaction(
            transaction_id=cls.generate_transaction_id(),
            network=normalized.network,
            asset=normalized.asset,
            sender=normalized.sender,
            recipient=normalized.recipient,
            amount=str(normalized.amount),
            nonce=normalized.nonce,
            gas_limit=normalized.gas_limit,
            gas_price=normalized.gas_price,
            max_fee_per_gas=normalized.max_fee_per_gas,
            max_priority_fee_per_gas=(
                normalized.max_priority_fee_per_gas
            ),
            fee_rate=normalized.fee_rate,
            token_contract=normalized.token_contract,
            token_standard=normalized.token_standard,
            decimals=normalized.decimals,
            reference=normalized.reference,
            payload=payload,
            payload_hash=cls.payload_hash(payload),
            metadata=dict(normalized.metadata),
        )

    # =========================================================================
    # DICTIONARY CONVENIENCE API
    # =========================================================================

    @classmethod
    def request_from_data(
        cls,
        *,
        network: str,
        **transaction_data: Any,
    ) -> TransactionRequest:
        """
        Construct a TransactionRequest from application data.

        This replaces callers reaching into private builder internals such as
        `_request_from_data`.
        """

        return TransactionRequest(
            network=network,
            asset=transaction_data.get("asset"),
            sender=transaction_data.get("sender"),
            recipient=transaction_data.get("recipient"),
            amount=transaction_data.get("amount"),
            nonce=transaction_data.get("nonce"),
            gas_limit=transaction_data.get("gas_limit"),
            gas_price=transaction_data.get("gas_price"),
            max_fee_per_gas=transaction_data.get(
                "max_fee_per_gas"
            ),
            max_priority_fee_per_gas=transaction_data.get(
                "max_priority_fee_per_gas"
            ),
            fee_rate=transaction_data.get("fee_rate"),
            token_contract=transaction_data.get(
                "token_contract"
            ),
            token_standard=transaction_data.get(
                "token_standard"
            ),
            decimals=transaction_data.get("decimals"),
            reference=transaction_data.get("reference"),
            metadata=transaction_data.get("metadata") or {},
        )

    # Backward-compatible private alias for existing callers.
    _request_from_data = request_from_data

    # =========================================================================
    # DJANGO VALIDATION HELPER
    # =========================================================================

    @classmethod
    def validate_for_django(
        cls,
        request: TransactionRequest,
    ) -> None:
        """
        Validate a transaction request and translate builder errors into
        Django ValidationError.

        Suitable for forms, serializers, and model validation boundaries.
        """

        try:
            cls.validate_request(
                request
            )

        except TransactionBuilderError as exc:
            raise ValidationError(
                str(exc)
            ) from exc
