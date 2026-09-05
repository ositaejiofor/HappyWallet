"""
HappyWallet Ethereum ERC-20 Token Transaction History Adapter.

This module retrieves public ERC-20 Transfer events from Ethereum JSON-RPC.

Security boundary
-----------------

This adapter is READ-ONLY.

It MUST NEVER:

    - access private keys
    - access wallet mnemonics
    - decrypt wallet secrets
    - access signing material
    - sign transactions
    - create transactions
    - broadcast transactions
    - approve token spending
    - transfer tokens
    - modify wallet records
    - persist transaction history
    - expose RPC credentials

Only public Ethereum blockchain data is accessed.

Architecture
------------

    Transaction History Service
                |
                v
       Ethereum Token Adapter
                |
                v
          Ethereum JSON-RPC

ERC-20 Transfer event
---------------------

    Transfer(address,address,uint256)

Encoded as:

    topic0 = keccak256("Transfer(address,address,uint256)")
    topic1 = indexed from address
    topic2 = indexed to address
    data   = uint256 token amount

Important limitation
--------------------

Ethereum JSON-RPC does not provide an address-indexed transaction-history
API.

This adapter therefore performs a bounded ``eth_getLogs`` scan.

For complete historical wallet activity at scale, an indexed blockchain
history provider should eventually be introduced.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .ethereum import _normalize_address_candidate


logger = logging.getLogger(__name__)


# ============================================================================
# TYPES
# ============================================================================

JSONDict = dict[str, Any]


# ============================================================================
# NETWORK CONSTANTS
# ============================================================================

ETHEREUM_NETWORK_NAME = "Ethereum Mainnet"

JSON_RPC_VERSION = "2.0"
JSON_RPC_REQUEST_ID = 1

RPC_METHOD_GET_BLOCK_NUMBER = "eth_blockNumber"
RPC_METHOD_GET_LOGS = "eth_getLogs"

USER_AGENT = "HappyWallet/1.0"

ETHEREUM_HEX_PREFIX = "0x"

ETHEREUM_ADDRESS_LENGTH = 42
ETHEREUM_ADDRESS_HEX_LENGTH = 40

ETHEREUM_HASH_LENGTH = 66

ETHEREUM_TOPIC_LENGTH = 66
ETHEREUM_TOPIC_DATA_HEX_LENGTH = 64


# ============================================================================
# ERC-20 CONSTANTS
# ============================================================================

ERC20_TRANSFER_EVENT_SIGNATURE = "Transfer(address,address,uint256)"

# keccak256("Transfer(address,address,uint256)")
ERC20_TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a9df523b3ef"
)

ERC20_TRANSFER_TOPIC_COUNT = 3

ERC20_TRANSFER_TOPIC_INDEX = 0
ERC20_FROM_TOPIC_INDEX = 1
ERC20_TO_TOPIC_INDEX = 2

ERC20_TRANSFER_DATA_HEX_LENGTH = 64


# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_TIMEOUT_SECONDS = 10
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 30

DEFAULT_BLOCK_LIMIT = 100
MIN_BLOCK_LIMIT = 1
MAX_BLOCK_LIMIT = 10_000

DEFAULT_MAX_TRANSFERS = 250
MIN_MAX_TRANSFERS = 1
MAX_MAX_TRANSFERS = 5_000

DEFAULT_TOKEN_DECIMALS = 18
MIN_TOKEN_DECIMALS = 0
MAX_TOKEN_DECIMALS = 255

DEFAULT_RETRY_ATTEMPTS = 2
MIN_RETRY_ATTEMPTS = 1
MAX_RETRY_ATTEMPTS = 3

DEFAULT_RETRY_BACKOFF_SECONDS = 0.25
MAX_RETRY_BACKOFF_SECONDS = 2.0

HTTP_SUCCESS_MIN = 200
HTTP_SUCCESS_MAX = 300

RETRYABLE_HTTP_STATUS_CODES = frozenset(
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


# ============================================================================
# EXCEPTIONS
# ============================================================================


class EthereumTokenHistoryError(RuntimeError):
    """Base exception for Ethereum ERC-20 history failures."""


class EthereumTokenRPCTemporaryError(EthereumTokenHistoryError):
    """
    Raised when an Ethereum RPC failure appears temporary.

    Callers may use this exception to distinguish infrastructure problems
    from malformed data or invalid configuration.
    """


# ============================================================================
# RESULT TYPES
# ============================================================================


@dataclass(frozen=True, slots=True)
class ERC20Transfer:
    """
    Immutable public representation of an ERC-20 transfer.

    No private or signing material is contained here.
    """

    transaction_hash: str

    token_address: str

    from_address: str
    to_address: str

    amount: Decimal
    raw_amount: int

    decimals: int

    symbol: str | None = None
    token_name: str | None = None

    network: str = ETHEREUM_NETWORK_NAME
    status: str = "confirmed"

    block_number: int | None = None
    transaction_index: int | None = None
    log_index: int | None = None

    timestamp: int | None = None

    direction: str = "unknown"


@dataclass(frozen=True, slots=True)
class ERC20TransferHistory:
    """
    Immutable ERC-20 transfer-history result.
    """

    transfers: tuple[ERC20Transfer, ...]
    available: bool


# ============================================================================
# PUBLIC API
# ============================================================================


def get_token_transfer_history(
    *,
    rpc_url: str,
    address: str,
    token_address: str | None = None,
    block_limit: int = DEFAULT_BLOCK_LIMIT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    max_transfers: int = DEFAULT_MAX_TRANSFERS,
    decimals: int = DEFAULT_TOKEN_DECIMALS,
    symbol: str | None = None,
    token_name: str | None = None,
) -> ERC20TransferHistory:
    """
    Retrieve recent ERC-20 transfers involving ``address``.

    This function performs public blockchain reads only.

    Parameters
    ----------
    rpc_url:
        Ethereum JSON-RPC endpoint.

    address:
        Wallet address whose transfers should be discovered.

    token_address:
        Optional ERC-20 contract address.

        When supplied, only events emitted by this contract are returned.

        When omitted, all ERC-20 Transfer events involving the wallet are
        searched.

    block_limit:
        Number of recent blocks to scan.

    timeout:
        Timeout for each RPC request.

    max_transfers:
        Maximum number of transfers returned.

    decimals:
        Token decimal precision used to convert raw token units.

        This must match the token contract's actual decimals.

    symbol:
        Optional token symbol.

    token_name:
        Optional token display name.
    """

    config = _normalize_configuration(
        rpc_url=rpc_url,
        address=address,
        token_address=token_address,
        block_limit=block_limit,
        timeout=timeout,
        max_transfers=max_transfers,
        decimals=decimals,
        symbol=symbol,
        token_name=token_name,
    )

    latest_block = _get_latest_block_number(
        rpc_url=config["rpc_url"],
        timeout=config["timeout"],
    )

    start_block = max(
        0,
        latest_block - config["block_limit"] + 1,
    )

    transfers: list[ERC20Transfer] = []
    seen_transfer_ids: set[tuple[str, int | None]] = set()

    chunk_size = _get_log_chunk_size(
        config["block_limit"],
    )

    for from_block, to_block in _iter_block_ranges(
        start_block=start_block,
        end_block=latest_block,
        chunk_size=chunk_size,
    ):
        if len(transfers) >= config["max_transfers"]:
            break

        logs = _get_transfer_logs(
            rpc_url=config["rpc_url"],
            wallet_address=config["address"],
            token_address=config["token_address"],
            from_block=from_block,
            to_block=to_block,
            timeout=config["timeout"],
        )

        for log in logs:
            if len(transfers) >= config["max_transfers"]:
                break

            transfer = _normalize_transfer_log(
                log=log,
                wallet_address=config["address"],
                decimals=config["decimals"],
                symbol=config["symbol"],
                token_name=config["token_name"],
            )

            if transfer is None:
                continue

            transfer_id = _transfer_identity(transfer)

            if transfer_id in seen_transfer_ids:
                continue

            seen_transfer_ids.add(transfer_id)
            transfers.append(transfer)

    transfers.sort(
        key=_transfer_sort_key,
        reverse=True,
    )

    return ERC20TransferHistory(
        transfers=tuple(
            transfers[: config["max_transfers"]]
        ),
        available=True,
    )


# ============================================================================
# CONFIGURATION
# ============================================================================


def _normalize_configuration(
    *,
    rpc_url: str,
    address: str,
    token_address: str | None,
    block_limit: int,
    timeout: int,
    max_transfers: int,
    decimals: int,
    symbol: str | None,
    token_name: str | None,
) -> JSONDict:
    """Validate and normalize all public API configuration."""

    normalized_token = (
        _normalize_address(token_address)
        if token_address is not None
        else None
    )

    return {
        "rpc_url": _validate_rpc_url(rpc_url),
        "address": _normalize_address(address),
        "token_address": normalized_token,
        "block_limit": _normalize_block_limit(block_limit),
        "timeout": _normalize_timeout(timeout),
        "max_transfers": _normalize_max_transfers(max_transfers),
        "decimals": _normalize_decimals(decimals),
        "symbol": _normalize_optional_text(symbol),
        "token_name": _normalize_optional_text(token_name),
    }


# ============================================================================
# LATEST BLOCK
# ============================================================================


def _get_latest_block_number(
    *,
    rpc_url: str,
    timeout: int,
) -> int:
    """Retrieve the current Ethereum chain head."""

    result = _rpc_call(
        rpc_url=rpc_url,
        method=RPC_METHOD_GET_BLOCK_NUMBER,
        params=[],
        timeout=timeout,
    )

    return _parse_required_quantity(
        result,
        field_name="latest block number",
    )


# ============================================================================
# ERC-20 LOG DISCOVERY
# ============================================================================


def _get_transfer_logs(
    *,
    rpc_url: str,
    wallet_address: str,
    token_address: str | None,
    from_block: int,
    to_block: int,
    timeout: int,
) -> tuple[JSONDict, ...]:
    """
    Retrieve ERC-20 Transfer logs involving the wallet.

    Two queries are intentionally performed:

        1. wallet as sender
        2. wallet as recipient

    This keeps the filter construction simple and provider-compatible.
    """

    wallet_topic = _address_to_topic(wallet_address)

    filters = (
        _build_transfer_filter(
            wallet_topic=wallet_topic,
            token_address=token_address,
            from_block=from_block,
            to_block=to_block,
            wallet_is_sender=True,
        ),
        _build_transfer_filter(
            wallet_topic=wallet_topic,
            token_address=token_address,
            from_block=from_block,
            to_block=to_block,
            wallet_is_sender=False,
        ),
    )

    collected: list[JSONDict] = []

    for log_filter in filters:
        result = _rpc_call(
            rpc_url=rpc_url,
            method=RPC_METHOD_GET_LOGS,
            params=[log_filter],
            timeout=timeout,
        )

        if not isinstance(result, list):
            raise EthereumTokenHistoryError(
                "Ethereum RPC returned an invalid log collection."
            )

        for item in result:
            if isinstance(item, dict):
                collected.append(item)

    return _deduplicate_logs(collected)


def _build_transfer_filter(
    *,
    wallet_topic: str,
    token_address: str | None,
    from_block: int,
    to_block: int,
    wallet_is_sender: bool,
) -> JSONDict:
    """Build an ``eth_getLogs`` filter for ERC-20 Transfer events."""

    if wallet_is_sender:
        topics: list[Any] = [
            ERC20_TRANSFER_TOPIC,
            [wallet_topic],
            None,
        ]
    else:
        topics = [
            ERC20_TRANSFER_TOPIC,
            None,
            [wallet_topic],
        ]

    result: JSONDict = {
        "fromBlock": _to_hex(from_block),
        "toBlock": _to_hex(to_block),
        "topics": topics,
    }

    if token_address is not None:
        result["address"] = token_address

    return result


def _deduplicate_logs(
    logs: list[JSONDict],
) -> tuple[JSONDict, ...]:
    """
    Deduplicate Ethereum logs.

    A self-transfer appears in both sender and recipient queries.
    """

    unique: list[JSONDict] = []
    seen: set[tuple[str, int | None]] = set()

    for log in logs:
        transaction_hash = _normalize_hash_candidate(
            log.get("transactionHash"),
        )

        if not transaction_hash:
            continue

        log_index = _parse_optional_quantity(
            log.get("logIndex"),
        )

        identity = (
            transaction_hash,
            log_index,
        )

        if identity in seen:
            continue

        seen.add(identity)
        unique.append(log)

    return tuple(unique)


# ============================================================================
# LOG NORMALIZATION
# ============================================================================


def _normalize_transfer_log(
    *,
    log: JSONDict,
    wallet_address: str,
    decimals: int,
    symbol: str | None,
    token_name: str | None,
) -> ERC20Transfer | None:
    """Convert one raw Ethereum log into an immutable ERC20Transfer."""

    if not isinstance(log, dict):
        return None

    # Ignore logs removed during a chain reorganization.
    if log.get("removed") is True:
        return None

    topics = log.get("topics")

    if not isinstance(topics, list):
        return None

    if len(topics) < ERC20_TRANSFER_TOPIC_COUNT:
        return None

    event_topic = _normalize_topic(
        topics[ERC20_TRANSFER_TOPIC_INDEX],
    )

    if event_topic != ERC20_TRANSFER_TOPIC:
        return None

    from_address = _decode_indexed_address(
        topics[ERC20_FROM_TOPIC_INDEX],
    )

    to_address = _decode_indexed_address(
        topics[ERC20_TO_TOPIC_INDEX],
    )

    if from_address is None or to_address is None:
        return None

    if wallet_address not in {
        from_address,
        to_address,
    }:
        return None

    transaction_hash = _normalize_hash_candidate(
        log.get("transactionHash"),
    )

    if not transaction_hash:
        return None

    token_address = _normalize_address_candidate(
        log.get("address"),
    )

    if not token_address:
        return None

    raw_amount = _decode_uint256(
        log.get("data"),
    )

    if raw_amount is None:
        return None

    amount = _raw_token_amount_to_decimal(
        raw_amount=raw_amount,
        decimals=decimals,
    )

    if amount is None:
        return None

    block_number = _parse_optional_quantity(
        log.get("blockNumber"),
    )

    transaction_index = _parse_optional_quantity(
        log.get("transactionIndex"),
    )

    log_index = _parse_optional_quantity(
        log.get("logIndex"),
    )

    return ERC20Transfer(
        transaction_hash=transaction_hash,
        token_address=token_address,
        from_address=from_address,
        to_address=to_address,
        amount=amount,
        raw_amount=raw_amount,
        decimals=decimals,
        symbol=symbol,
        token_name=token_name,
        network=ETHEREUM_NETWORK_NAME,
        status="confirmed",
        block_number=block_number,
        transaction_index=transaction_index,
        log_index=log_index,
        timestamp=None,
        direction=_get_transfer_direction(
            wallet_address=wallet_address,
            from_address=from_address,
            to_address=to_address,
        ),
    )


def _get_transfer_direction(
    *,
    wallet_address: str,
    from_address: str,
    to_address: str,
) -> str:
    """Determine transfer direction relative to the wallet."""

    if (
        from_address == wallet_address
        and to_address == wallet_address
    ):
        return "self"

    if to_address == wallet_address:
        return "incoming"

    if from_address == wallet_address:
        return "outgoing"

    return "unknown"


# ============================================================================
# ERC-20 TOPIC DECODING
# ============================================================================


def _address_to_topic(address: str) -> str:
    """Convert an Ethereum address into a 32-byte indexed topic."""

    normalized = _normalize_address(address)

    return (
        ETHEREUM_HEX_PREFIX
        + ("0" * 24)
        + normalized[2:]
    )


def _decode_indexed_address(
    topic: Any,
) -> str | None:
    """
    Decode an indexed Ethereum address from a 32-byte topic.

    ERC-20 indexed addresses occupy the final 20 bytes.
    """

    normalized = _normalize_topic(topic)

    if normalized is None:
        return None

    address_hex = normalized[
        -ETHEREUM_ADDRESS_HEX_LENGTH:
    ]

    if not _is_hex_payload(address_hex):
        return None

    return ETHEREUM_HEX_PREFIX + address_hex


def _decode_uint256(
    value: Any,
) -> int | None:
    """Decode a uint256 amount from ERC-20 Transfer event data."""

    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    if not normalized.startswith(ETHEREUM_HEX_PREFIX):
        return None

    payload = normalized[2:]

    if len(payload) != ERC20_TRANSFER_DATA_HEX_LENGTH:
        return None

    if not _is_hex_payload(payload):
        return None

    try:
        return int(payload, 16)
    except ValueError:
        return None


def _normalize_topic(
    value: Any,
) -> str | None:
    """Validate and normalize a 32-byte Ethereum topic."""

    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    if len(normalized) != ETHEREUM_TOPIC_LENGTH:
        return None

    if not normalized.startswith(ETHEREUM_HEX_PREFIX):
        return None

    payload = normalized[2:]

    if len(payload) != ETHEREUM_TOPIC_DATA_HEX_LENGTH:
        return None

    if not _is_hex_payload(payload):
        return None

    return normalized


# ============================================================================
# TOKEN AMOUNT
# ============================================================================


def _raw_token_amount_to_decimal(
    raw_amount: int,
    decimals: int,
) -> Decimal | None:
    """
    Convert raw ERC-20 units to Decimal.

    Floating-point arithmetic is deliberately avoided.
    """

    if isinstance(raw_amount, bool):
        return None

    if not isinstance(raw_amount, int):
        return None

    if raw_amount < 0:
        return None

    if isinstance(decimals, bool):
        return None

    if not isinstance(decimals, int):
        return None

    if not (
        MIN_TOKEN_DECIMALS
        <= decimals
        <= MAX_TOKEN_DECIMALS
    ):
        return None

    try:
        divisor = Decimal(10) ** decimals
        amount = Decimal(raw_amount) / divisor
    except (
        InvalidOperation,
        ZeroDivisionError,
    ):
        return None

    if not amount.is_finite():
        return None

    return amount


# ============================================================================
# TRANSFER IDENTITY
# ============================================================================


def _transfer_identity(
    transfer: ERC20Transfer,
) -> tuple[str, int | None]:
    """
    Return the canonical identity of a transfer event.

    Transaction hash alone is insufficient because a single transaction
    can contain multiple ERC-20 Transfer events.
    """

    return (
        transfer.transaction_hash,
        transfer.log_index,
    )


# ============================================================================
# BLOCK RANGE
# ============================================================================


def _iter_block_ranges(
    *,
    start_block: int,
    end_block: int,
    chunk_size: int,
) -> Iterator[tuple[int, int]]:
    """
    Yield bounded block ranges from newest to oldest.
    """

    if start_block > end_block:
        return

    if chunk_size < 1:
        raise EthereumTokenHistoryError(
            "Ethereum log chunk size must be greater than zero."
        )

    current_end = end_block

    while current_end >= start_block:
        current_start = max(
            start_block,
            current_end - chunk_size + 1,
        )

        yield current_start, current_end

        current_end = current_start - 1


def _get_log_chunk_size(
    block_limit: int,
) -> int:
    """
    Return the block range used by individual eth_getLogs calls.

    This remains isolated so provider-specific chunking can be introduced
    later without changing the public API.
    """

    return min(
        block_limit,
        MAX_BLOCK_LIMIT,
    )


# ============================================================================
# SORTING
# ============================================================================


def _transfer_sort_key(
    transfer: ERC20Transfer,
) -> tuple[int, int, int]:
    """Sort newest transfers first."""

    return (
        transfer.block_number
        if transfer.block_number is not None
        else -1,
        transfer.transaction_index
        if transfer.transaction_index is not None
        else -1,
        transfer.log_index
        if transfer.log_index is not None
        else -1,
    )


# ============================================================================
# JSON-RPC
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
    Perform a bounded Ethereum JSON-RPC request.

    The RPC URL and request body are never written to logs.
    """

    request_body = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")

    attempts = _get_retry_attempts()
    last_error: Exception | None = None

    for attempt in range(attempts):
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
                raise EthereumTokenHistoryError(
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

                raise EthereumTokenHistoryError(
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

        except OSError as exc:
            last_error = exc

            logger.warning(
                "Ethereum RPC operating-system transport failure.",
                extra={
                    "method": method,
                    "error_type": type(exc).__name__,
                    "attempt": attempt + 1,
                },
            )

        if attempt + 1 < attempts:
            _sleep_before_retry(attempt=attempt)

    raise EthereumTokenRPCTemporaryError(
        "Ethereum RPC connection failed."
    ) from last_error


def _decode_rpc_response(
    raw_body: bytes,
    *,
    method: str,
) -> Any:
    """Decode and validate a JSON-RPC response."""

    try:
        response_data = json.loads(
            raw_body.decode("utf-8"),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        logger.warning(
            "Ethereum RPC returned invalid JSON.",
            extra={"method": method},
        )

        raise EthereumTokenHistoryError(
            "Ethereum RPC returned invalid JSON."
        ) from exc

    if not isinstance(response_data, dict):
        raise EthereumTokenHistoryError(
            "Ethereum RPC returned an invalid response."
        )

    if response_data.get("jsonrpc") != JSON_RPC_VERSION:
        raise EthereumTokenHistoryError(
            "Ethereum RPC returned an invalid protocol version."
        )

    if response_data.get("id") != JSON_RPC_REQUEST_ID:
        raise EthereumTokenHistoryError(
            "Ethereum RPC returned an invalid response identifier."
        )

    rpc_error = response_data.get("error")

    if rpc_error is not None:
        error_code = None

        if isinstance(rpc_error, dict):
            error_code = rpc_error.get("code")

        logger.warning(
            "Ethereum RPC provider returned an error.",
            extra={
                "method": method,
                "error_code": error_code,
            },
        )

        raise EthereumTokenHistoryError(
            "Ethereum RPC returned an error."
        )

    if "result" not in response_data:
        raise EthereumTokenHistoryError(
            "Ethereum RPC response contained no result."
        )

    return response_data["result"]


# ============================================================================
# RETRY
# ============================================================================


def _get_retry_attempts() -> int:
    """Return the bounded retry count."""

    return min(
        max(
            DEFAULT_RETRY_ATTEMPTS,
            MIN_RETRY_ATTEMPTS,
        ),
        MAX_RETRY_ATTEMPTS,
    )


def _sleep_before_retry(
    *,
    attempt: int,
) -> None:
    """Apply bounded exponential retry backoff."""

    delay = min(
        DEFAULT_RETRY_BACKOFF_SECONDS * (2**attempt),
        MAX_RETRY_BACKOFF_SECONDS,
    )

    time.sleep(delay)


# ============================================================================
# ADDRESS VALIDATION
# ============================================================================


def _normalize_address(
    address: str,
) -> str:
    """Validate and normalize an Ethereum address."""

    if not isinstance(address, str):
        raise EthereumTokenHistoryError(
            "Ethereum address must be a string."
        )

    normalized = address.strip().lower()

    if not normalized:
        raise EthereumTokenHistoryError(
            "Ethereum address is empty."
        )

    if len(normalized) != ETHEREUM_ADDRESS_LENGTH:
        raise EthereumTokenHistoryError(
            "Invalid Ethereum address length."
        )

    if not normalized.startswith(ETHEREUM_HEX_PREFIX):
        raise EthereumTokenHistoryError(
            "Invalid Ethereum address."
        )

    if not _is_hex_payload(normalized[2:]):
        raise EthereumTokenHistoryError(
            "Invalid Ethereum address."
        )

    return normalized


# ============================================================================
# HASH VALIDATION
# ============================================================================


def _normalize_hash_candidate(
    value: Any,
) -> str:
    """
    Normalize a transaction hash returned by an external provider.

    Invalid values return an empty string.
    """

    if not isinstance(value, str):
        return ""

    normalized = value.strip().lower()

    if not _is_valid_transaction_hash(normalized):
        return ""

    return normalized


def _is_valid_transaction_hash(
    value: str,
) -> bool:
    """Validate a 32-byte Ethereum transaction hash."""

    if not isinstance(value, str):
        return False

    normalized = value.strip().lower()

    if len(normalized) != ETHEREUM_HASH_LENGTH:
        return False

    if not normalized.startswith(ETHEREUM_HEX_PREFIX):
        return False

    return _is_hex_payload(normalized[2:])


# ============================================================================
# HEX VALIDATION
# ============================================================================


def _is_hex_payload(
    value: str,
) -> bool:
    """Return True when ``value`` contains hexadecimal characters only."""

    if not isinstance(value, str):
        return False

    if not value:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


# ============================================================================
# NUMBER VALIDATION
# ============================================================================


def _parse_optional_quantity(
    value: Any,
) -> int | None:
    """
    Parse an Ethereum quantity.

    Hexadecimal strings are accepted for JSON-RPC data.

    Decimal strings and integers are also accepted to make fixtures and
    tests easier to construct.
    """

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value if value >= 0 else None

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    if not normalized:
        return None

    try:
        if normalized.lower().startswith(ETHEREUM_HEX_PREFIX):
            parsed = int(normalized, 16)
        else:
            parsed = int(normalized, 10)
    except ValueError:
        return None

    return parsed if parsed >= 0 else None


def _parse_required_quantity(
    value: Any,
    *,
    field_name: str,
) -> int:
    """Parse a required Ethereum numeric quantity."""

    parsed = _parse_optional_quantity(value)

    if parsed is None:
        raise EthereumTokenHistoryError(
            f"Invalid Ethereum {field_name}."
        )

    return parsed


def _to_hex(
    value: int,
) -> str:
    """Convert a non-negative integer to Ethereum quantity notation."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise EthereumTokenHistoryError(
            "Ethereum block number must be an integer."
        )

    if value < 0:
        raise EthereumTokenHistoryError(
            "Ethereum block number cannot be negative."
        )

    return hex(value)


# ============================================================================
# CONFIGURATION NORMALIZATION
# ============================================================================


def _normalize_block_limit(
    value: int,
) -> int:
    """Normalize the maximum block scan."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise EthereumTokenHistoryError(
            "Invalid Ethereum block limit."
        )

    if value < MIN_BLOCK_LIMIT:
        raise EthereumTokenHistoryError(
            "Ethereum block limit must be greater than zero."
        )

    return min(value, MAX_BLOCK_LIMIT)


def _normalize_timeout(
    value: int,
) -> int:
    """Normalize the RPC timeout."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise EthereumTokenHistoryError(
            "Invalid Ethereum RPC timeout."
        )

    if value < MIN_TIMEOUT_SECONDS:
        raise EthereumTokenHistoryError(
            "Ethereum RPC timeout is too small."
        )

    return min(value, MAX_TIMEOUT_SECONDS)


def _normalize_max_transfers(
    value: int,
) -> int:
    """Normalize the maximum number of returned transfers."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise EthereumTokenHistoryError(
            "Invalid maximum transfer limit."
        )

    if value < MIN_MAX_TRANSFERS:
        raise EthereumTokenHistoryError(
            "Maximum transfer limit must be greater than zero."
        )

    return min(value, MAX_MAX_TRANSFERS)


def _normalize_decimals(
    value: int,
) -> int:
    """Normalize ERC-20 token decimals."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise EthereumTokenHistoryError(
            "Invalid ERC-20 decimals."
        )

    if not (
        MIN_TOKEN_DECIMALS
        <= value
        <= MAX_TOKEN_DECIMALS
    ):
        raise EthereumTokenHistoryError(
            "ERC-20 decimals must be between 0 and 255."
        )

    return value


def _normalize_optional_text(
    value: str | None,
) -> str | None:
    """Normalize optional token metadata."""

    if value is None:
        return None

    if not isinstance(value, str):
        raise EthereumTokenHistoryError(
            "Token metadata must be text."
        )

    normalized = value.strip()

    return normalized or None


# ============================================================================
# RPC URL VALIDATION
# ============================================================================


def _validate_rpc_url(
    rpc_url: str,
) -> str:
    """
    Validate an Ethereum RPC endpoint.

    The complete URL is never written to logs.
    """

    if not isinstance(rpc_url, str):
        raise EthereumTokenHistoryError(
            "Ethereum RPC URL must be a string."
        )

    normalized = rpc_url.strip()

    if not normalized:
        raise EthereumTokenHistoryError(
            "Ethereum RPC URL is not configured."
        )

    parsed = urlparse(normalized)

    if parsed.scheme not in {"http", "https"}:
        raise EthereumTokenHistoryError(
            "Ethereum RPC URL must use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise EthereumTokenHistoryError(
            "Ethereum RPC URL is invalid."
        )

    return normalized


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================


__all__ = [
    "ERC20Transfer",
    "ERC20TransferHistory",
    "EthereumTokenHistoryError",
    "EthereumTokenRPCTemporaryError",
    "get_token_transfer_history",
    "ERC20_TRANSFER_EVENT_SIGNATURE",
    "ERC20_TRANSFER_TOPIC",
]