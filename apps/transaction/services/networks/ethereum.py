"""
HappyWallet Ethereum transaction-history adapter.

Public-data boundary
--------------------

This module retrieves PUBLIC Ethereum blockchain transaction metadata.

It MUST NEVER:

    - access private keys
    - access wallet mnemonics
    - decrypt wallet secrets
    - access signing material
    - sign transactions
    - build transactions
    - broadcast transactions
    - modify wallet records
    - persist transaction history
    - expose RPC credentials in logs or exceptions


Architecture
------------

    TransactionHistoryService
              |
              v
      EthereumHistoryAdapter
              |
              +------------------------------+
              |                              |
              v                              v
    Indexed Alchemy History          Generic Ethereum JSON-RPC
    (when Alchemy is detected)       bounded recent-block scan


Provider strategy
-----------------

Alchemy endpoints use:

    alchemy_getAssetTransfers

This is an indexed history API and is substantially more appropriate for
address transaction history than scanning complete Ethereum blocks.

Non-Alchemy endpoints retain the existing bounded JSON-RPC block-scan
fallback.

The application-level DTO remains unchanged so callers do not need to know
which provider strategy was used.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Final
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

ETHEREUM_NETWORK_NAME: Final = "Ethereum Mainnet"
ETHEREUM_SYMBOL: Final = "ETH"

JSON_RPC_VERSION: Final = "2.0"
JSON_RPC_REQUEST_ID: Final = 1

RPC_METHOD_GET_BLOCK_NUMBER: Final = "eth_blockNumber"
RPC_METHOD_GET_BLOCK_BY_NUMBER: Final = "eth_getBlockByNumber"
RPC_METHOD_GET_TRANSACTION_BY_HASH: Final = "eth_getTransactionByHash"

# Alchemy indexed transaction-history method.
RPC_METHOD_ALCHEMY_GET_ASSET_TRANSFERS: Final = (
    "alchemy_getAssetTransfers"
)

# Alchemy limits one request to at most 1,000 transfers.
ALCHEMY_MAX_COUNT: Final = 1_000

# Native ETH transfer categories.
#
# "external" represents normal ETH transfers.
# "internal" represents ETH value movements caused by contract execution.
#
# Keep this tuple unchanged because the indexed-history request contract
# intentionally requests native ETH categories.
ALCHEMY_NATIVE_CATEGORIES: Final[tuple[str, ...]] = (
    "external",
    "internal",
)

ALCHEMY_FROM_BLOCK: Final = "0x0"
ALCHEMY_TO_BLOCK: Final = "latest"
ALCHEMY_EXCLUDE_ZERO_VALUE: Final = False
ALCHEMY_WITH_METADATA: Final = True

# Request complete transaction objects from the generic block scanner.
RPC_INCLUDE_FULL_TRANSACTIONS: Final = True

HEX_PREFIX: Final = "0x"

ETHEREUM_ADDRESS_LENGTH: Final = 42
ETHEREUM_HASH_LENGTH: Final = 66
ETHEREUM_NATIVE_DECIMALS: Final = 18

DEFAULT_TIMEOUT_SECONDS: Final = 10
MIN_TIMEOUT_SECONDS: Final = 1
MAX_TIMEOUT_SECONDS: Final = 30

DEFAULT_BLOCK_LIMIT: Final = 5
MIN_BLOCK_LIMIT: Final = 1
MAX_BLOCK_LIMIT: Final = 25

DEFAULT_MAX_TRANSACTIONS: Final = 250
MIN_MAX_TRANSACTIONS: Final = 1
MAX_MAX_TRANSACTIONS: Final = 1_000

DEFAULT_RETRY_ATTEMPTS: Final = 2
MIN_RETRY_ATTEMPTS: Final = 1
MAX_RETRY_ATTEMPTS: Final = 3

DEFAULT_RETRY_BACKOFF_SECONDS: Final = 0.25
MAX_RETRY_BACKOFF_SECONDS: Final = 2.0

RETRYABLE_HTTP_STATUS_CODES: Final[frozenset[int]] = frozenset(
    {
        408,
        425,
        429,
        500,
        502,
        503,
        504,
    }
)

HTTP_SUCCESS_MIN: Final = 200
HTTP_SUCCESS_MAX: Final = 300

USER_AGENT: Final = "HappyWallet/1.0"


# ============================================================================
# TYPE ALIASES
# ============================================================================

JSONDict = dict[str, Any]


# ============================================================================
# EXCEPTIONS
# ============================================================================


class EthereumHistoryError(RuntimeError):
    """Base exception for Ethereum history failures."""


class EthereumRPCTemporaryError(EthereumHistoryError):
    """Raised when an Ethereum RPC transport failure remains retryable."""


# ============================================================================
# RESULT TYPES
# ============================================================================


@dataclass(frozen=True, slots=True)
class EthereumTransaction:
    """Immutable public representation of an Ethereum transaction."""

    transaction_hash: str
    transaction_type: str
    status: str

    network: str = ETHEREUM_NETWORK_NAME
    amount: Decimal | None = None
    symbol: str | None = ETHEREUM_SYMBOL
    block_number: int | None = None
    timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class EthereumTransactionHistory:
    """Immutable Ethereum transaction-history result."""

    transactions: tuple[EthereumTransaction, ...]
    available: bool


# ============================================================================
# PUBLIC API
# ============================================================================


def get_indexed_transaction_history(
    *,
    rpc_url: str,
    address: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
) -> EthereumTransactionHistory:
    """
    Retrieve indexed Ethereum transaction history through Alchemy.

    The wallet address is queried as both:

        - fromAddress
        - toAddress

    This captures both outgoing and incoming transfers.

    The original address representation supplied by the caller is preserved
    in the Alchemy request.

    Address comparisons remain case-insensitive.

    Results are deduplicated by transaction hash and bounded by
    ``max_transactions``.

    This function does not access wallet secrets or database state.
    """

    rpc_endpoint = _validate_rpc_url(
        rpc_url,
    )

    wallet_address = _prepare_indexed_wallet_address(
        address,
    )

    request_timeout = _normalize_timeout(
        timeout,
    )

    transaction_limit = _normalize_max_transactions(
        max_transactions,
    )

    transactions: list[EthereumTransaction] = []
    seen_hashes: set[str] = set()

    for address_filter in (
        "fromAddress",
        "toAddress",
    ):
        if len(transactions) >= transaction_limit:
            break

        page_key: str | None = None

        while len(transactions) < transaction_limit:
            remaining = (
                transaction_limit
                - len(transactions)
            )

            params: JSONDict = {
                "fromBlock": ALCHEMY_FROM_BLOCK,
                "toBlock": ALCHEMY_TO_BLOCK,
                address_filter: wallet_address,
                "category": list(
                    ALCHEMY_NATIVE_CATEGORIES,
                ),
                "excludeZeroValue": (
                    ALCHEMY_EXCLUDE_ZERO_VALUE
                ),
                "withMetadata": (
                    ALCHEMY_WITH_METADATA
                ),
                "maxCount": hex(
                    min(
                        ALCHEMY_MAX_COUNT,
                        remaining,
                    )
                ),
            }

            if page_key:
                params["pageKey"] = page_key

            result = _rpc_call(
                rpc_url=rpc_endpoint,
                method=RPC_METHOD_ALCHEMY_GET_ASSET_TRANSFERS,
                params=[params],
                timeout=request_timeout,
            )

            if not isinstance(
                result,
                dict,
            ):
                raise EthereumHistoryError(
                    "Alchemy returned an invalid transfer response."
                )

            raw_transfers = result.get(
                "transfers",
            )

            if raw_transfers is None:
                raw_transfers = []

            if not isinstance(
                raw_transfers,
                list,
            ):
                raise EthereumHistoryError(
                    "Alchemy returned an invalid transfer collection."
                )

            for transfer in raw_transfers:
                if len(transactions) >= transaction_limit:
                    break

                normalized = _normalize_alchemy_transfer(
                    transfer=transfer,
                    wallet_address=wallet_address,
                )

                if normalized is None:
                    continue

                transaction_hash = normalized.transaction_hash

                if transaction_hash in seen_hashes:
                    continue

                seen_hashes.add(
                    transaction_hash,
                )

                transactions.append(
                    normalized,
                )

            next_page_key = result.get(
                "pageKey",
            )

            if not isinstance(
                next_page_key,
                str,
            ):
                break

            next_page_key = next_page_key.strip()

            if not next_page_key:
                break

            if next_page_key == page_key:
                logger.warning(
                    "Alchemy returned an unchanged transaction-history page key."
                )
                break

            page_key = next_page_key

    # Consistent newest-first ordering.
    transactions.sort(
        key=lambda transaction: (
            transaction.block_number
            if transaction.block_number is not None
            else -1,
            transaction.timestamp
            if transaction.timestamp is not None
            else -1,
        ),
        reverse=True,
    )

    return EthereumTransactionHistory(
        transactions=tuple(
            transactions[:transaction_limit],
        ),
        available=True,
    )


def get_transaction_history(
    *,
    rpc_url: str,
    address: str,
    block_limit: int = DEFAULT_BLOCK_LIMIT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
) -> EthereumTransactionHistory:
    """
    Retrieve public Ethereum transactions involving ``address``.

    Provider strategy:

        Alchemy RPC:
            Use indexed ``alchemy_getAssetTransfers``.

        Other providers:
            Use the bounded recent-block JSON-RPC fallback.

    No wallet secrets, signing material, or database state are accessed.
    """

    rpc_endpoint = _validate_rpc_url(
        rpc_url,
    )

    if _is_alchemy_rpc_url(
        rpc_endpoint,
    ):
        return get_indexed_transaction_history(
            rpc_url=rpc_endpoint,
            address=address,
            timeout=timeout,
            max_transactions=max_transactions,
        )

    return _get_transaction_history_via_blocks(
        rpc_url=rpc_endpoint,
        address=address,
        block_limit=block_limit,
        timeout=timeout,
        max_transactions=max_transactions,
    )


# ============================================================================
# PROVIDER DETECTION
# ============================================================================


def _is_alchemy_rpc_url(
    rpc_url: str,
) -> bool:
    """
    Return True when the RPC hostname belongs to Alchemy.
    """

    parsed = urlparse(
        rpc_url,
    )

    hostname = (
        parsed.hostname or ""
    ).strip().lower()

    return hostname.endswith(
        ".alchemy.com",
    )


# ============================================================================
# INDEXED ADDRESS VALIDATION
# ============================================================================


def _prepare_indexed_wallet_address(
    address: str,
) -> str:
    """
    Validate an Ethereum wallet address while preserving its representation.

    ``_normalize_address()`` is intentionally not used as the return value
    here because it lowercases addresses.

    Alchemy requests may contain checksum/mixed-case addresses, while all
    internal comparisons remain case-insensitive.
    """

    if not isinstance(
        address,
        str,
    ):
        raise EthereumHistoryError(
            "Ethereum wallet address must be a string."
        )

    wallet_address = address.strip()

    if not wallet_address:
        raise EthereumHistoryError(
            "Ethereum wallet address is empty."
        )

    # Validate the address without replacing its representation.
    _normalize_address(
        wallet_address,
    )

    return wallet_address


# ============================================================================
# GENERIC BLOCK-SCAN FALLBACK
# ============================================================================


def _get_transaction_history_via_blocks(
    *,
    rpc_url: str,
    address: str,
    block_limit: int,
    timeout: int,
    max_transactions: int,
) -> EthereumTransactionHistory:
    """
    Retrieve transaction history using a bounded block scan.

    This remains the generic fallback for providers that do not expose
    an indexed address-history API.
    """

    wallet_address = _normalize_address(
        address,
    )

    scan_limit = _normalize_block_limit(
        block_limit,
    )

    request_timeout = _normalize_timeout(
        timeout,
    )

    transaction_limit = _normalize_max_transactions(
        max_transactions,
    )

    latest_block = _get_latest_block_number(
        rpc_url=rpc_url,
        timeout=request_timeout,
    )

    start_block = max(
        0,
        latest_block - scan_limit + 1,
    )

    transactions: list[EthereumTransaction] = []
    seen_hashes: set[str] = set()

    for block_number in range(
        latest_block,
        start_block - 1,
        -1,
    ):
        if len(transactions) >= transaction_limit:
            break

        block = _get_block(
            rpc_url=rpc_url,
            block_number=block_number,
            timeout=request_timeout,
        )

        if block is None:
            continue

        timestamp = _parse_optional_hex_int(
            block.get("timestamp"),
        )

        raw_transactions = _extract_block_transactions(
            block.get("transactions"),
        )

        if not raw_transactions:
            continue

        resolved_transactions = _resolve_block_transactions(
            rpc_url=rpc_url,
            raw_transactions=raw_transactions,
            timeout=request_timeout,
        )

        for raw_transaction in resolved_transactions:
            if len(transactions) >= transaction_limit:
                break

            if not _transaction_involves_address(
                transaction=raw_transaction,
                address=wallet_address,
            ):
                continue

            transaction = _normalize_transaction(
                transaction=raw_transaction,
                block_number=block_number,
                timestamp=timestamp,
            )

            if transaction is None:
                continue

            if transaction.transaction_hash in seen_hashes:
                continue

            seen_hashes.add(
                transaction.transaction_hash,
            )

            transactions.append(
                transaction,
            )

    return EthereumTransactionHistory(
        transactions=tuple(
            transactions,
        ),
        available=True,
    )


# ============================================================================
# ALCHEMY TRANSFER NORMALIZATION
# ============================================================================


def _normalize_alchemy_transfer(
    *,
    transfer: Any,
    wallet_address: str,
) -> EthereumTransaction | None:
    """
    Convert one public Alchemy transfer record into the application DTO.

    Supported categories:

        - external
        - internal
        - erc20

    Native ETH transfers use 18 decimals.

    ERC-20 transfers use ``rawContract.decimals``.

    Invalid, unrelated, or unsupported transfers are ignored.

    No wallet secrets, signing material, or database state are accessed.
    """

    if not isinstance(
        transfer,
        dict,
    ):
        return None

    transaction_hash = _normalize_transaction_hash(
        transfer.get("hash"),
    )

    if transaction_hash is None:
        return None

    sender = _normalize_address_candidate(
        transfer.get("from"),
    )

    recipient = _normalize_address_candidate(
        transfer.get("to"),
    )

    normalized_wallet = wallet_address.strip().lower()

    if (
        sender != normalized_wallet
        and recipient != normalized_wallet
    ):
        return None

    category = _normalize_alchemy_category(
        transfer.get("category"),
    )

    if category is None:
        return None

    block_number = _parse_optional_hex_int(
        transfer.get("blockNum"),
    )

    timestamp = _alchemy_transfer_timestamp(
        transfer,
    )

    if category in ALCHEMY_NATIVE_CATEGORIES:
        amount = _alchemy_native_transfer_amount(
            transfer,
        )
        symbol = ETHEREUM_SYMBOL

    elif category == "erc20":
        amount = _alchemy_token_transfer_amount(
            transfer,
        )
        symbol = _alchemy_transfer_symbol(
            transfer,
        )

    else:
        return None

    return EthereumTransaction(
        transaction_hash=transaction_hash,
        transaction_type="transfer",
        status="confirmed",
        network=ETHEREUM_NETWORK_NAME,
        amount=amount,
        symbol=symbol,
        block_number=block_number,
        timestamp=timestamp,
    )


def _normalize_alchemy_category(
    value: Any,
) -> str | None:
    """
    Normalize an Alchemy transfer category.
    """

    if not isinstance(
        value,
        str,
    ):
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    return normalized


def _alchemy_transfer_symbol(
    transfer: dict[str, Any],
) -> str | None:
    """
    Extract the public asset symbol from an Alchemy transfer.

    Empty or malformed symbols are represented as ``None``.
    """

    asset = transfer.get(
        "asset",
    )

    if not isinstance(
        asset,
        str,
    ):
        return None

    normalized = asset.strip()

    if not normalized:
        return None

    return normalized


def _alchemy_native_transfer_amount(
    transfer: dict[str, Any],
) -> Decimal | None:
    """
    Resolve a native ETH transfer amount.

    ``rawContract.value`` is preferred because it preserves the exact wei
    quantity.

    The human-readable ``value`` field is used as fallback.
    """

    raw_contract = transfer.get(
        "rawContract",
    )

    if isinstance(
        raw_contract,
        dict,
    ):
        raw_value = raw_contract.get(
            "value",
        )

        if isinstance(
            raw_value,
            str,
        ):
            normalized = raw_value.strip()

            if normalized.lower().startswith(
                HEX_PREFIX,
            ):
                try:
                    wei = int(
                        normalized,
                        16,
                    )
                except ValueError:
                    wei = None

                if wei is not None:
                    return _wei_to_eth(
                        wei,
                    )

    return _safe_decimal(
        transfer.get(
            "value",
        ),
    )


def _alchemy_token_transfer_amount(
    transfer: dict[str, Any],
) -> Decimal | None:
    """
    Resolve an ERC-20 transfer amount using the token's decimals.

    Example:

        rawContract.value    = "0x5f5e100"
        rawContract.decimals = 6

    produces:

        Decimal("100")
    """

    raw_contract = transfer.get(
        "rawContract",
    )

    if isinstance(
        raw_contract,
        dict,
    ):
        raw_value = raw_contract.get(
            "value",
        )

        decimals = raw_contract.get(
            "decimals",
        )

        if (
            isinstance(
                raw_value,
                str,
            )
            and isinstance(
                decimals,
                int,
            )
            and not isinstance(
                decimals,
                bool,
            )
            and 0 <= decimals <= 255
        ):
            normalized = raw_value.strip()

            if normalized:
                try:
                    if normalized.lower().startswith(
                        HEX_PREFIX,
                    ):
                        raw_integer = int(
                            normalized,
                            16,
                        )
                    else:
                        raw_integer = int(
                            normalized,
                            10,
                        )
                except (
                    TypeError,
                    ValueError,
                ):
                    raw_integer = None

                if raw_integer is not None:
                    if raw_integer < 0:
                        return None

                    try:
                        amount = Decimal(
                            raw_integer,
                        ) / (
                            Decimal(10)
                            ** decimals
                        )
                    except (
                        InvalidOperation,
                        ZeroDivisionError,
                    ):
                        return None

                    if not amount.is_finite():
                        return None

                    return amount

    # Provider compatibility fallback.
    #
    # Alchemy's human-readable ``value`` is already expressed in token
    # units.
    return _safe_decimal(
        transfer.get(
            "value",
        ),
    )


def _safe_decimal(
    value: Any,
) -> Decimal | None:
    """
    Convert a provider value to a finite Decimal.

    No binary floating-point conversion is performed.
    """

    if value is None:
        return None

    try:
        decimal_value = Decimal(
            str(value),
        )
    except (
        InvalidOperation,
        ValueError,
        TypeError,
    ):
        return None

    if not decimal_value.is_finite():
        return None

    return decimal_value


def _alchemy_transfer_timestamp(
    transfer: dict[str, Any],
) -> int | None:
    """
    Convert Alchemy metadata blockTimestamp into Unix seconds.
    """

    metadata = transfer.get(
        "metadata",
    )

    if not isinstance(
        metadata,
        dict,
    ):
        return None

    timestamp = metadata.get(
        "blockTimestamp",
    )

    if not isinstance(
        timestamp,
        str,
    ):
        return None

    normalized = timestamp.strip()

    if not normalized:
        return None

    try:
        parsed = datetime.fromisoformat(
            normalized.replace(
                "Z",
                "+00:00",
            ),
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc,
        )

    return int(
        parsed.timestamp(),
    )


# ============================================================================
# LATEST BLOCK
# ============================================================================


def _get_latest_block_number(
    *,
    rpc_url: str,
    timeout: int,
) -> int:
    """Retrieve the latest Ethereum block number."""

    result = _rpc_call(
        rpc_url=rpc_url,
        method=RPC_METHOD_GET_BLOCK_NUMBER,
        params=[],
        timeout=timeout,
    )

    return _parse_required_hex_int(
        result,
        field_name="latest block number",
    )


# ============================================================================
# BLOCK RETRIEVAL
# ============================================================================


def _get_block(
    *,
    rpc_url: str,
    block_number: int,
    timeout: int,
) -> JSONDict | None:
    """
    Retrieve a single Ethereum block.

    Transactions are requested as complete objects so the generic fallback
    does not require one additional RPC call per transaction hash.
    """

    result = _rpc_call(
        rpc_url=rpc_url,
        method=RPC_METHOD_GET_BLOCK_BY_NUMBER,
        params=[
            _to_hex_quantity(
                block_number,
            ),
            RPC_INCLUDE_FULL_TRANSACTIONS,
        ],
        timeout=timeout,
    )

    if result is None:
        return None

    if not isinstance(
        result,
        dict,
    ):
        raise EthereumHistoryError(
            "Ethereum RPC returned an invalid block."
        )

    return result


def _extract_block_transactions(
    value: Any,
) -> tuple[Any, ...]:
    """Validate and normalize a block transaction collection."""

    if not isinstance(
        value,
        (list, tuple),
    ):
        raise EthereumHistoryError(
            "Ethereum block returned an invalid transaction collection."
        )

    return tuple(
        value,
    )


# ============================================================================
# TRANSACTION RESOLUTION
# ============================================================================


def _resolve_block_transactions(
    *,
    rpc_url: str,
    raw_transactions: tuple[Any, ...],
    timeout: int,
) -> tuple[JSONDict, ...]:
    """
    Resolve block transactions.

    Supported representations:

        - complete transaction dictionaries
        - transaction hashes

    Invalid individual entries are ignored.
    """

    resolved: list[JSONDict] = []
    transaction_hashes: list[str] = []

    for item in raw_transactions:
        if isinstance(
            item,
            dict,
        ):
            resolved.append(
                item,
            )
            continue

        normalized_hash = _normalize_transaction_hash(
            item,
        )

        if normalized_hash is not None:
            transaction_hashes.append(
                normalized_hash,
            )

    if not transaction_hashes:
        return tuple(
            resolved,
        )

    resolved.extend(
        _get_transactions_by_hashes(
            rpc_url=rpc_url,
            transaction_hashes=transaction_hashes,
            timeout=timeout,
        )
    )

    return tuple(
        resolved,
    )


def _get_transactions_by_hashes(
    *,
    rpc_url: str,
    transaction_hashes: list[str] | tuple[str, ...],
    timeout: int,
) -> tuple[JSONDict, ...]:
    """
    Resolve transaction hashes individually.

    A failed individual lookup does not invalidate the remainder of the
    block's transaction collection.
    """

    if not isinstance(
        transaction_hashes,
        (list, tuple),
    ):
        raise EthereumHistoryError(
            "Invalid transaction hash collection."
        )

    transactions: list[JSONDict] = []

    for transaction_hash in transaction_hashes:
        normalized_hash = _normalize_transaction_hash(
            transaction_hash,
        )

        if normalized_hash is None:
            continue

        try:
            result = _rpc_call(
                rpc_url=rpc_url,
                method=RPC_METHOD_GET_TRANSACTION_BY_HASH,
                params=[
                    normalized_hash,
                ],
                timeout=timeout,
            )

        except EthereumHistoryError as exc:
            logger.warning(
                "Ethereum transaction lookup failed.",
                extra={
                    "method": RPC_METHOD_GET_TRANSACTION_BY_HASH,
                    "error_type": type(exc).__name__,
                },
            )
            continue

        if isinstance(
            result,
            dict,
        ):
            transactions.append(
                result,
            )

    return tuple(
        transactions,
    )


# ============================================================================
# RPC TRANSPORT
# ============================================================================


def _rpc_call(
    *,
    rpc_url: str,
    method: str,
    params: list[Any],
    timeout: int,
) -> Any:
    """Execute one Ethereum JSON-RPC request."""

    payload: JSONDict = {
        "jsonrpc": JSON_RPC_VERSION,
        "id": JSON_RPC_REQUEST_ID,
        "method": method,
        "params": params,
    }

    return _perform_rpc_request(
        rpc_url=rpc_url,
        payload=payload,
        timeout=timeout,
        method=method,
    )


def _perform_rpc_request(
    *,
    rpc_url: str,
    payload: JSONDict,
    timeout: int,
    method: str,
) -> Any:
    """
    Execute an HTTP JSON-RPC request with bounded retries.

    The endpoint itself is deliberately absent from all logs and exception
    messages.
    """

    request_body = json.dumps(
        payload,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8",
    )

    attempts = _get_retry_attempts()
    last_error: Exception | None = None

    for attempt in range(
        attempts,
    ):
        request = Request(
            rpc_url,
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )

        try:
            with urlopen(
                request,
                timeout=timeout,
            ) as response:
                status_code = getattr(
                    response,
                    "status",
                    None,
                )

                raw_body = response.read()

            if (
                status_code is not None
                and not (
                    HTTP_SUCCESS_MIN
                    <= status_code
                    < HTTP_SUCCESS_MAX
                )
            ):
                raise EthereumHistoryError(
                    "Ethereum RPC returned an unexpected HTTP status."
                )

            return _decode_rpc_response(
                raw_body,
                method=method,
            )

        except HTTPError as exc:
            last_error = exc

            if exc.code not in RETRYABLE_HTTP_STATUS_CODES:
                logger.warning(
                    "Ethereum RPC HTTP request failed.",
                    extra={
                        "method": method,
                        "status_code": exc.code,
                    },
                )

                raise EthereumHistoryError(
                    "Ethereum RPC HTTP request failed."
                ) from exc

            logger.warning(
                "Transient Ethereum RPC HTTP failure.",
                extra={
                    "method": method,
                    "status_code": exc.code,
                    "attempt": attempt + 1,
                },
            )

        except (
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
            ConnectionResetError,
            BrokenPipeError,
            URLError,
            socket.timeout,
            TimeoutError,
            OSError,
        ) as exc:
            last_error = exc

            logger.warning(
                "Ethereum RPC transport failure.",
                extra={
                    "method": method,
                    "error_type": type(exc).__name__,
                    "attempt": attempt + 1,
                },
            )

        if attempt + 1 < attempts:
            _sleep_before_retry(
                attempt,
            )

    raise EthereumRPCTemporaryError(
        "Ethereum RPC connection failed."
    ) from last_error


# ============================================================================
# RPC RESPONSE VALIDATION
# ============================================================================


def _decode_rpc_response(
    raw_body: bytes,
    *,
    method: str,
) -> Any:
    """
    Decode and validate a JSON-RPC response.

    Required:

        - JSON-RPC 2.0
        - expected request ID
        - no provider error
        - result field
    """

    try:
        response = json.loads(
            raw_body.decode(
                "utf-8",
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        logger.warning(
            "Ethereum RPC returned invalid JSON.",
            extra={
                "method": method,
            },
        )

        raise EthereumHistoryError(
            "Ethereum RPC returned invalid JSON."
        ) from exc

    if not isinstance(
        response,
        dict,
    ):
        raise EthereumHistoryError(
            "Ethereum RPC returned an invalid response."
        )

    if response.get(
        "jsonrpc",
    ) != JSON_RPC_VERSION:
        raise EthereumHistoryError(
            "Ethereum RPC returned an invalid protocol version."
        )

    if response.get(
        "id",
    ) != JSON_RPC_REQUEST_ID:
        raise EthereumHistoryError(
            "Ethereum RPC returned an invalid response identifier."
        )

    rpc_error = response.get(
        "error",
    )

    if rpc_error is not None:
        error_code = (
            rpc_error.get(
                "code",
            )
            if isinstance(
                rpc_error,
                dict,
            )
            else None
        )

        logger.warning(
            "Ethereum RPC provider returned an error.",
            extra={
                "method": method,
                "error_code": error_code,
            },
        )

        raise EthereumHistoryError(
            "Ethereum RPC returned an error."
        )

    if "result" not in response:
        raise EthereumHistoryError(
            "Ethereum RPC response contained no result."
        )

    return response["result"]


# ============================================================================
# RETRY
# ============================================================================


def _get_retry_attempts() -> int:
    """Return the bounded RPC retry count."""

    return min(
        max(
            DEFAULT_RETRY_ATTEMPTS,
            MIN_RETRY_ATTEMPTS,
        ),
        MAX_RETRY_ATTEMPTS,
    )


def _sleep_before_retry(
    attempt: int,
) -> None:
    """Apply bounded exponential retry backoff."""

    delay = min(
        DEFAULT_RETRY_BACKOFF_SECONDS
        * (
            2**attempt
        ),
        MAX_RETRY_BACKOFF_SECONDS,
    )

    time.sleep(
        delay,
    )


# ============================================================================
# TRANSACTION NORMALIZATION
# ============================================================================


def _normalize_transaction(
    *,
    transaction: JSONDict,
    block_number: int,
    timestamp: int | None,
) -> EthereumTransaction | None:
    """
    Convert raw public transaction data into the application DTO.
    """

    if not isinstance(
        transaction,
        dict,
    ):
        return None

    transaction_hash = _normalize_transaction_hash(
        transaction.get(
            "hash",
        ),
    )

    if transaction_hash is None:
        return None

    return EthereumTransaction(
        transaction_hash=transaction_hash,
        transaction_type=_classify_transaction_type(
            transaction.get(
                "input",
            ),
        ),
        status="confirmed",
        network=ETHEREUM_NETWORK_NAME,
        amount=_wei_to_eth(
            transaction.get(
                "value",
            ),
        ),
        symbol=ETHEREUM_SYMBOL,
        block_number=block_number,
        timestamp=timestamp,
    )


def _classify_transaction_type(
    input_data: Any,
) -> str:
    """
    Classify the transaction at a basic ETH-transaction level.

    Empty calldata:
        transfer

    Non-empty calldata:
        contract

    Invalid calldata:
        unknown
    """

    if not isinstance(
        input_data,
        str,
    ):
        return "unknown"

    normalized = input_data.strip().lower()

    if normalized in {
        "",
        HEX_PREFIX,
    }:
        return "transfer"

    return "contract"


# ============================================================================
# ADDRESS FILTERING
# ============================================================================


def _transaction_involves_address(
    *,
    transaction: JSONDict,
    address: str,
) -> bool:
    """Return whether sender or recipient matches ``address``."""

    if not isinstance(
        transaction,
        dict,
    ):
        return False

    normalized_address = _normalize_address(
        address,
    )

    sender = _normalize_address_candidate(
        transaction.get(
            "from",
        ),
    )

    recipient = _normalize_address_candidate(
        transaction.get(
            "to",
        ),
    )

    return normalized_address in {
        sender,
        recipient,
    }


def _normalize_address_candidate(
    value: Any,
) -> str:
    """Normalize an optional Ethereum address candidate."""

    if not isinstance(
        value,
        str,
    ):
        return ""

    normalized = value.strip().lower()

    if len(normalized) != ETHEREUM_ADDRESS_LENGTH:
        return ""

    if not normalized.startswith(
        HEX_PREFIX,
    ):
        return ""

    if not _is_hex_payload(
        normalized[2:],
    ):
        return ""

    return normalized


def _normalize_address(
    address: str,
) -> str:
    """
    Validate and normalize a required Ethereum wallet address.

    The returned value is lowercase for internal comparisons.
    """

    if not isinstance(
        address,
        str,
    ):
        raise EthereumHistoryError(
            "Ethereum wallet address must be a string."
        )

    normalized = address.strip().lower()

    if not normalized:
        raise EthereumHistoryError(
            "Ethereum wallet address is empty."
        )

    if len(normalized) != ETHEREUM_ADDRESS_LENGTH:
        raise EthereumHistoryError(
            "Invalid Ethereum wallet address length."
        )

    if not normalized.startswith(
        HEX_PREFIX,
    ):
        raise EthereumHistoryError(
            "Invalid Ethereum wallet address."
        )

    if not _is_hex_payload(
        normalized[2:],
    ):
        raise EthereumHistoryError(
            "Invalid Ethereum wallet address."
        )

    return normalized


def _is_hex_payload(
    value: str,
) -> bool:
    """Return True when ``value`` contains only hexadecimal characters."""

    if not isinstance(
        value,
        str,
    ) or not value:
        return False

    try:
        int(
            value,
            16,
        )
    except ValueError:
        return False

    return True


def _normalize_transaction_hash(
    value: Any,
) -> str | None:
    """Normalize and validate an Ethereum transaction hash."""

    if not isinstance(
        value,
        str,
    ):
        return None

    normalized = value.strip().lower()

    if len(normalized) != ETHEREUM_HASH_LENGTH:
        return None

    if not normalized.startswith(
        HEX_PREFIX,
    ):
        return None

    if not _is_hex_payload(
        normalized[2:],
    ):
        return None

    return normalized


# ============================================================================
# NUMBER HELPERS
# ============================================================================


def _parse_required_hex_int(
    value: Any,
    *,
    field_name: str,
) -> int:
    """Parse a required Ethereum numeric quantity."""

    parsed = _parse_optional_hex_int(
        value,
    )

    if parsed is None:
        raise EthereumHistoryError(
            f"Invalid Ethereum {field_name}."
        )

    return parsed


def _parse_optional_hex_int(
    value: Any,
) -> int | None:
    """
    Parse an optional Ethereum numeric quantity.

    Both hexadecimal and decimal strings are accepted for compatibility
    with fixtures and providers.
    """

    if value is None or isinstance(
        value,
        bool,
    ):
        return None

    if isinstance(
        value,
        int,
    ):
        return value if value >= 0 else None

    if not isinstance(
        value,
        str,
    ):
        return None

    normalized = value.strip()

    if not normalized:
        return None

    try:
        if normalized.lower().startswith(
            HEX_PREFIX,
        ):
            parsed = int(
                normalized,
                16,
            )
        else:
            parsed = int(
                normalized,
                10,
            )
    except ValueError:
        return None

    return parsed if parsed >= 0 else None


def _to_hex_quantity(
    value: int,
) -> str:
    """Convert a non-negative integer to Ethereum quantity notation."""

    if isinstance(
        value,
        bool,
    ) or not isinstance(
        value,
        int,
    ):
        raise EthereumHistoryError(
            "Ethereum block number must be an integer."
        )

    if value < 0:
        raise EthereumHistoryError(
            "Ethereum block number cannot be negative."
        )

    return hex(
        value,
    )


def _normalize_block_limit(
    value: int,
) -> int:
    """Validate and bound the block scan size."""

    if isinstance(
        value,
        bool,
    ):
        raise EthereumHistoryError(
            "Invalid Ethereum block limit."
        )

    try:
        normalized = int(
            value,
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise EthereumHistoryError(
            "Invalid Ethereum block limit."
        ) from exc

    if normalized < MIN_BLOCK_LIMIT:
        raise EthereumHistoryError(
            "Ethereum block limit must be greater than zero."
        )

    return min(
        normalized,
        MAX_BLOCK_LIMIT,
    )


def _normalize_timeout(
    value: int,
) -> int:
    """Validate and bound the RPC timeout."""

    if isinstance(
        value,
        bool,
    ):
        raise EthereumHistoryError(
            "Invalid Ethereum RPC timeout."
        )

    try:
        normalized = int(
            value,
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise EthereumHistoryError(
            "Invalid Ethereum RPC timeout."
        ) from exc

    if normalized < MIN_TIMEOUT_SECONDS:
        raise EthereumHistoryError(
            "Ethereum RPC timeout is too small."
        )

    return min(
        normalized,
        MAX_TIMEOUT_SECONDS,
    )


def _normalize_max_transactions(
    value: int,
) -> int:
    """Validate and bound the transaction result limit."""

    if isinstance(
        value,
        bool,
    ):
        raise EthereumHistoryError(
            "Invalid maximum transaction limit."
        )

    try:
        normalized = int(
            value,
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise EthereumHistoryError(
            "Invalid maximum transaction limit."
        ) from exc

    if normalized < MIN_MAX_TRANSACTIONS:
        raise EthereumHistoryError(
            "Maximum transaction limit must be greater than zero."
        )

    return min(
        normalized,
        MAX_MAX_TRANSACTIONS,
    )


# ============================================================================
# AMOUNT
# ============================================================================


def _wei_to_eth(
    value: Any,
) -> Decimal | None:
    """
    Convert a wei quantity to ETH without floating-point arithmetic.
    """

    if value is None or isinstance(
        value,
        bool,
    ):
        return None

    try:
        if isinstance(
            value,
            str,
        ):
            normalized = value.strip()

            if not normalized:
                return None

            if normalized.lower().startswith(
                HEX_PREFIX,
            ):
                wei = int(
                    normalized,
                    16,
                )
            else:
                wei = int(
                    normalized,
                    10,
                )

        elif isinstance(
            value,
            int,
        ):
            wei = value

        else:
            return None

    except (
        TypeError,
        ValueError,
    ):
        return None

    if wei < 0:
        return None

    try:
        amount = Decimal(
            wei,
        ) / Decimal(
            10**ETHEREUM_NATIVE_DECIMALS,
        )
    except (
        InvalidOperation,
        ZeroDivisionError,
    ):
        return None

    if not amount.is_finite():
        return None

    return amount


# ============================================================================
# RPC URL VALIDATION
# ============================================================================


def _validate_rpc_url(
    rpc_url: str,
) -> str:
    """
    Validate an Ethereum JSON-RPC endpoint.

    Only HTTP and HTTPS URLs with a network location are accepted.

    The endpoint is never logged or included in exception messages.
    """

    if not isinstance(
        rpc_url,
        str,
    ):
        raise EthereumHistoryError(
            "Ethereum RPC URL must be a string."
        )

    normalized = rpc_url.strip()

    if not normalized:
        raise EthereumHistoryError(
            "Ethereum RPC URL is not configured."
        )

    parsed = urlparse(
        normalized,
    )

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise EthereumHistoryError(
            "Ethereum RPC URL must use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise EthereumHistoryError(
            "Ethereum RPC URL is invalid."
        )

    return normalized


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================

__all__ = [
    "EthereumHistoryError",
    "EthereumRPCTemporaryError",
    "EthereumTransaction",
    "EthereumTransactionHistory",
    "get_indexed_transaction_history",
    "get_transaction_history",
]