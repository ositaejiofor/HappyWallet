"""
HappyWallet Transaction History Service.

Application-level boundary for public blockchain transaction history.

Security boundary
-----------------

This module MUST NEVER:

    - access private keys
    - access wallet mnemonics
    - decrypt wallet secrets
    - access signing material
    - sign transactions
    - broadcast transactions
    - create blockchain transactions
    - modify wallet records
    - persist provider transaction history
    - expose provider credentials

Only public wallet information may be passed to network adapters.

Design goals
------------

- Fail closed on malformed provider responses.
- Never allow provider-specific DTOs to escape this service.
- Normalize all public wallet/network data at the boundary.
- Keep application DTOs immutable.
- Never log RPC credentials.
- Treat unsupported networks as unavailable.
- Treat malformed provider results as unavailable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ValidationError

from apps.wallet.models import Wallet, WalletAddress

from .networks.ethereum import (
    EthereumHistoryError,
    EthereumTransaction,
    get_transaction_history,
)


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_TRANSACTION_TYPE = "unknown"
DEFAULT_TRANSACTION_STATUS = "unknown"
DEFAULT_NETWORK_NAME = "Unknown Network"

DEFAULT_ETHEREUM_BLOCK_LIMIT = 5
MIN_ETHEREUM_BLOCK_LIMIT = 1
MAX_ETHEREUM_BLOCK_LIMIT = 100

ETHEREUM_NETWORK_IDENTIFIERS = frozenset(
    {
        "ethereum",
        "ethereum-mainnet",
        "ethereum-main-net",
        "eth",
        "eth-mainnet",
        "mainnet",
    }
)


# ============================================================================
# APPLICATION DTOs
# ============================================================================


@dataclass(frozen=True, slots=True)
class WalletTransaction:
    """
    Immutable application-level public blockchain transaction.

    Provider-specific transaction objects must never escape this module.
    """

    transaction_hash: str
    transaction_type: str
    status: str
    network: str
    amount: Decimal | None = None
    symbol: str | None = None
    block_number: int | None = None
    timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class TransactionHistory:
    """
    Immutable application-level transaction-history result.

    available=True
        The provider was successfully queried.

    available=True with no transactions
        The provider responded successfully but no matching
        transactions were found.

    available=False
        Transaction history could not safely be resolved.
    """

    transactions: tuple[WalletTransaction, ...]
    available: bool

    def __post_init__(self) -> None:
        if not isinstance(self.transactions, tuple):
            object.__setattr__(
                self,
                "transactions",
                tuple(self.transactions),
            )

        object.__setattr__(
            self,
            "available",
            bool(self.available),
        )


# ============================================================================
# PUBLIC SERVICE
# ============================================================================


def get_wallet_transaction_history(
    *,
    wallet: Wallet | None,
) -> TransactionHistory:
    """
    Resolve public blockchain transaction history for a wallet.

    This function never accesses wallet secrets or signing material.

    The service fails closed whenever required public information is
    missing or a provider returns malformed data.
    """

    if wallet is None:
        return _unavailable_transaction_history(
            reason="wallet_missing",
        )

    address = _get_public_address(wallet)

    if not address:
        return _unavailable_transaction_history(
            reason="wallet_address_missing",
        )

    network = _get_wallet_network(wallet)

    if network is None:
        return _unavailable_transaction_history(
            reason="wallet_network_missing",
        )

    network_identifier = _get_network_identifier(network)

    if not network_identifier:
        return _unavailable_transaction_history(
            reason="network_identifier_missing",
        )

    if _is_ethereum_network(network_identifier):
        return _get_ethereum_transaction_history(
            address=address,
        )

    logger.warning(
        "Transaction history requested for unsupported network.",
        extra={
            "network": network_identifier,
        },
    )

    return _unavailable_transaction_history(
        reason="unsupported_network",
    )


# ============================================================================
# WALLET PUBLIC DATA
# ============================================================================


def _get_public_address(
    wallet: Wallet,
) -> str:
    """
    Resolve the wallet's public blockchain address.

    Resolution order:

        1. wallet.address
        2. Active WalletAddress for the configured network
        3. Any active WalletAddress belonging to the wallet

    Only public address information is accessed.
    """

    direct_address = _normalize_public_address(
        getattr(wallet, "address", None),
    )

    if direct_address:
        return direct_address

    wallet_pk = _get_model_primary_key(wallet)

    if wallet_pk is None:
        return ""

    network = _get_wallet_network(wallet)

    if network is not None:
        network_pk = _get_model_primary_key(network)

        if network_pk is not None:
            address = _query_wallet_address(
                wallet_pk=wallet_pk,
                network_pk=network_pk,
            )

            if address:
                return address

    return _query_wallet_address(
        wallet_pk=wallet_pk,
    )


def _query_wallet_address(
    *,
    wallet_pk: UUID,
    network_pk: UUID | None = None,
) -> str:
    """
    Resolve one active public wallet address.

    Invalid ORM/model data fails closed.
    """

    try:
        queryset = WalletAddress.objects.filter(
            wallet_id=wallet_pk,
            is_active=True,
        )

        if network_pk is not None:
            queryset = queryset.filter(
                network_id=network_pk,
            )

        for wallet_address in queryset.order_by("id"):
            address = _normalize_public_address(
                getattr(
                    wallet_address,
                    "address",
                    None,
                ),
            )

            if address:
                return address

    except (
        ValidationError,
        ValueError,
        TypeError,
    ):
        logger.debug(
            "Wallet public-address lookup received invalid model data.",
        )

    except Exception:
        logger.exception(
            "Unexpected failure while resolving wallet public address.",
        )

    return ""


def _get_model_primary_key(
    model: Any,
) -> UUID | None:
    """
    Resolve a model-like object's UUID primary key.

    Supports both ``pk`` and ``id``.
    """

    if model is None:
        return None

    value = getattr(
        model,
        "pk",
        None,
    )

    if value is None:
        value = getattr(
            model,
            "id",
            None,
        )

    return _coerce_uuid(value)


def _coerce_uuid(
    value: Any,
) -> UUID | None:
    """
    Safely convert a UUID-compatible value into UUID.
    """

    if value is None:
        return None

    if isinstance(value, UUID):
        return value

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    if not normalized:
        return None

    try:
        return UUID(normalized)
    except (
        ValueError,
        TypeError,
        AttributeError,
    ):
        return None


def _normalize_public_address(
    value: Any,
) -> str:
    """
    Normalize a public blockchain address.

    Blockchain-specific validation remains the responsibility
    of the network adapter.
    """

    if not isinstance(value, str):
        return ""

    return value.strip()


def _get_wallet_network(
    wallet: Wallet,
) -> Any | None:
    """
    Return the wallet's configured public network metadata.
    """

    return getattr(
        wallet,
        "network",
        None,
    )


def _get_network_identifier(
    network: Any,
) -> str:
    """
    Resolve a stable public network identifier.

    Resolution priority:

        slug
        code
        identifier
        key
        name
    """

    if network is None:
        return ""

    for field_name in (
        "slug",
        "code",
        "identifier",
        "key",
        "name",
    ):
        value = getattr(
            network,
            field_name,
            None,
        )

        if not isinstance(value, str):
            continue

        normalized = _normalize_network_identifier(
            value,
        )

        if normalized:
            return normalized

    return ""


# ============================================================================
# NETWORK IDENTIFICATION
# ============================================================================


def _normalize_network_identifier(
    value: Any,
) -> str:
    """
    Normalize common network identifier variations.
    """

    if not isinstance(value, str):
        return ""

    return (
        value
        .strip()
        .lower()
        .replace("_", "-")
        .replace(" ", "-")
    )


def _is_ethereum_network(
    network_identifier: str,
) -> bool:
    """
    Return True when the identifier represents Ethereum Mainnet.
    """

    normalized = _normalize_network_identifier(
        network_identifier,
    )

    return normalized in ETHEREUM_NETWORK_IDENTIFIERS


# ============================================================================
# ETHEREUM HISTORY
# ============================================================================


def _get_ethereum_transaction_history(
    *,
    address: str,
) -> TransactionHistory:
    """
    Resolve Ethereum transaction history through the Ethereum adapter.

    This function validates the provider boundary before accessing
    provider-result attributes.

    Any malformed provider response fails closed.
    """

    rpc_url = _get_ethereum_rpc_url()

    if not rpc_url:
        return _unavailable_transaction_history(
            reason="ethereum_rpc_url_missing",
        )

    block_limit = _get_ethereum_block_limit()

    try:
        result = get_transaction_history(
            rpc_url=rpc_url,
            address=address,
            block_limit=block_limit,
        )

    except EthereumHistoryError as exc:
        logger.warning(
            "Ethereum transaction history provider failure.",
            extra={
                "error_type": type(exc).__name__,
            },
        )

        return _unavailable_transaction_history(
            reason="ethereum_provider_error",
        )

    except TimeoutError:
        logger.warning(
            "Ethereum transaction history request timed out.",
        )

        return _unavailable_transaction_history(
            reason="ethereum_provider_timeout",
        )

    except Exception as exc:
        logger.error(
            "Unexpected Ethereum transaction history failure.",
            extra={
                "error_type": type(exc).__name__,
            },
        )

        return _unavailable_transaction_history(
            reason="unexpected_provider_error",
        )

    # ------------------------------------------------------------------------
    # PROVIDER RESPONSE VALIDATION
    # ------------------------------------------------------------------------

    if result is None:
        logger.warning(
            "Ethereum transaction history adapter returned None.",
        )

        return _unavailable_transaction_history(
            reason="empty_provider_response",
        )

    if not _is_valid_ethereum_history_result(result):
        logger.warning(
            "Ethereum transaction history adapter returned an invalid result.",
            extra={
                "result_type": type(result).__name__,
            },
        )

        return _unavailable_transaction_history(
            reason="invalid_provider_response",
        )

    if not result.available:
        logger.warning(
            "Ethereum transaction history adapter reported unavailable.",
        )

        return _unavailable_transaction_history(
            reason="provider_unavailable",
        )

    transactions = _convert_ethereum_transactions(
        result.transactions,
    )

    return TransactionHistory(
        transactions=transactions,
        available=True,
    )


def _is_valid_ethereum_history_result(
    result: Any,
) -> bool:
    """
    Validate the minimum provider-result contract.

    The Ethereum adapter is expected to return an object containing:

        available
        transactions

    A malformed object must never cause AttributeError to escape
    into the application layer.
    """

    if result is None:
        return False

    try:
        available = getattr(
            result,
            "available",
        )

        transactions = getattr(
            result,
            "transactions",
        )

    except (
        AttributeError,
        TypeError,
    ):
        return False

    if not isinstance(
        available,
        bool,
    ):
        return False

    if transactions is None:
        return True

    return isinstance(
        transactions,
        (tuple, list),
    )


# ============================================================================
# ETHEREUM CONFIGURATION
# ============================================================================


def _get_ethereum_rpc_url() -> str:
    """
    Resolve the Ethereum RPC endpoint from Django settings.

    The endpoint is never logged or exposed.
    """

    value = getattr(
        settings,
        "ETHEREUM_RPC_URL",
        "",
    )

    if not isinstance(value, str):
        return ""

    return value.strip()


def _get_ethereum_block_limit() -> int:
    """
    Resolve and safely bound the Ethereum block scan limit.

    Setting:

        TRANSACTION_HISTORY_BLOCK_LIMIT
    """

    value = getattr(
        settings,
        "TRANSACTION_HISTORY_BLOCK_LIMIT",
        DEFAULT_ETHEREUM_BLOCK_LIMIT,
    )

    if isinstance(value, bool):
        return DEFAULT_ETHEREUM_BLOCK_LIMIT

    try:
        block_limit = int(value)
    except (
        TypeError,
        ValueError,
    ):
        return DEFAULT_ETHEREUM_BLOCK_LIMIT

    if block_limit < MIN_ETHEREUM_BLOCK_LIMIT:
        return DEFAULT_ETHEREUM_BLOCK_LIMIT

    return min(
        block_limit,
        MAX_ETHEREUM_BLOCK_LIMIT,
    )


# ============================================================================
# PROVIDER DTO CONVERSION
# ============================================================================


def _convert_ethereum_transactions(
    transactions: Any,
) -> tuple[WalletTransaction, ...]:
    """
    Convert provider transaction DTOs into application DTOs.

    Invalid collections fail closed to an empty tuple.
    """

    if transactions is None:
        return ()

    if not isinstance(
        transactions,
        (tuple, list),
    ):
        logger.warning(
            "Ethereum adapter returned an invalid transaction collection.",
            extra={
                "collection_type": type(transactions).__name__,
            },
        )

        return ()

    converted: list[WalletTransaction] = []

    for transaction in transactions:
        normalized = _convert_ethereum_transaction(
            transaction,
        )

        if normalized is not None:
            converted.append(normalized)

    return tuple(converted)


def _convert_ethereum_transaction(
    transaction: EthereumTransaction | None,
) -> WalletTransaction | None:
    """
    Convert one Ethereum provider DTO into an application DTO.

    Invalid transactions are discarded instead of escaping the
    application boundary.
    """

    if transaction is None:
        return None

    transaction_hash = _safe_required_string(
        getattr(
            transaction,
            "transaction_hash",
            None,
        ),
    )

    if not transaction_hash:
        return None

    return WalletTransaction(
        transaction_hash=transaction_hash,
        transaction_type=_safe_string(
            getattr(
                transaction,
                "transaction_type",
                None,
            ),
            default=DEFAULT_TRANSACTION_TYPE,
        ),
        status=_safe_string(
            getattr(
                transaction,
                "status",
                None,
            ),
            default=DEFAULT_TRANSACTION_STATUS,
        ),
        network=_safe_string(
            getattr(
                transaction,
                "network",
                None,
            ),
            default=DEFAULT_NETWORK_NAME,
        ),
        amount=_safe_decimal(
            getattr(
                transaction,
                "amount",
                None,
            ),
        ),
        symbol=_safe_optional_string(
            getattr(
                transaction,
                "symbol",
                None,
            ),
        ),
        block_number=_safe_non_negative_int(
            getattr(
                transaction,
                "block_number",
                None,
            ),
        ),
        timestamp=_safe_non_negative_int(
            getattr(
                transaction,
                "timestamp",
                None,
            ),
        ),
    )


# ============================================================================
# NORMALIZATION HELPERS
# ============================================================================


def _safe_required_string(
    value: Any,
) -> str | None:
    """
    Normalize a required string.
    """

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    return normalized or None


def _safe_string(
    value: Any,
    *,
    default: str,
) -> str:
    """
    Normalize a string with a safe fallback.
    """

    if not isinstance(value, str):
        return default

    normalized = value.strip()

    return normalized or default


def _safe_optional_string(
    value: Any,
) -> str | None:
    """
    Normalize an optional string.
    """

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    return normalized or None


def _safe_decimal(
    value: Any,
) -> Decimal | None:
    """
    Safely normalize a Decimal-compatible value.
    """

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, Decimal):
        decimal_value = value

    elif isinstance(value, int):
        decimal_value = Decimal(value)

    elif isinstance(value, float):
        try:
            decimal_value = Decimal(str(value))
        except Exception:
            return None

    elif isinstance(value, str):
        normalized = value.strip()

        if not normalized:
            return None

        try:
            decimal_value = Decimal(normalized)
        except Exception:
            return None

    else:
        return None

    if not decimal_value.is_finite():
        return None

    return decimal_value


def _safe_non_negative_int(
    value: Any,
) -> int | None:
    """
    Normalize a non-negative integer.
    """

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value if value >= 0 else None

    if isinstance(value, str):
        normalized = value.strip()

        if not normalized:
            return None

        try:
            parsed = int(
                normalized,
                10,
            )
        except ValueError:
            return None

        return parsed if parsed >= 0 else None

    return None


# ============================================================================
# RESULT HELPERS
# ============================================================================


def _unavailable_transaction_history(
    *,
    reason: str = "unknown",
) -> TransactionHistory:
    """
    Construct the canonical unavailable transaction-history result.

    ``reason`` is internal diagnostic information only.
    It is never exposed to callers.
    """

    logger.debug(
        "Transaction history unavailable.",
        extra={
            "reason": reason,
        },
    )

    return TransactionHistory(
        transactions=(),
        available=False,
    )


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "TransactionHistory",
    "WalletTransaction",
    "get_wallet_transaction_history",
]
