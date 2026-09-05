"""
HappyWallet Alchemy Ethereum Transaction History Adapter.

Retrieves PUBLIC Ethereum transaction-transfer history through Alchemy's
indexed JSON-RPC API.

Security boundary
-----------------

This adapter MUST NEVER:

    - access private keys
    - access mnemonics
    - decrypt wallet secrets
    - sign transactions
    - broadcast transactions
    - create transactions
    - modify wallet records
    - persist transaction history
    - expose RPC credentials

Only public blockchain information is processed.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

ETHEREUM_NETWORK_NAME = "Ethereum Mainnet"
ETHEREUM_SYMBOL = "ETH"

JSON_RPC_VERSION = "2.0"

RPC_METHOD_ASSET_TRANSFERS = "alchemy_getAssetTransfers"

DEFAULT_TIMEOUT_SECONDS = 30
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 30

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 100

DEFAULT_MAX_PAGES = 10
MIN_MAX_PAGES = 1
MAX_MAX_PAGES = 20

ETHEREUM_ADDRESS_LENGTH = 42
ETHEREUM_HASH_LENGTH = 66


# ============================================================================
# EXCEPTIONS
# ============================================================================


class AlchemyHistoryError(RuntimeError):
    """Base exception for Alchemy history failures."""


# ============================================================================
# RESULT TYPES
# ============================================================================


@dataclass(frozen=True, slots=True)
class AlchemyTransaction:
    """Immutable public transaction-transfer representation."""

    transaction_hash: str
    transaction_type: str
    status: str

    network: str = ETHEREUM_NETWORK_NAME

    amount: Decimal | None = None
    symbol: str | None = ETHEREUM_SYMBOL

    block_number: int | None = None
    timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class AlchemyTransactionHistory:
    """Immutable Alchemy history result."""

    transactions: tuple[AlchemyTransaction, ...]
    available: bool


# ============================================================================
# PUBLIC API
# ============================================================================


def get_transaction_history(
    *,
    rpc_url: str,
    address: str,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_pages: int = DEFAULT_MAX_PAGES,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> AlchemyTransactionHistory:
    """
    Retrieve indexed Ethereum transfer history for ``address``.

    Both outgoing and incoming transfers are queried.

    Results are paginated using Alchemy's pageKey mechanism.

    No wallet secrets are accessed.
    """

    _validate_rpc_url(rpc_url)

    normalized_address = _normalize_address(address)

    page_size = _normalize_page_size(page_size)
    max_pages = _normalize_max_pages(max_pages)
    timeout = _normalize_timeout(timeout)

    transfers: list[dict[str, Any]] = []

    for direction in ("fromAddress", "toAddress"):
        transfers.extend(
            _get_directional_transfers(
                rpc_url=rpc_url,
                address=normalized_address,
                direction=direction,
                page_size=page_size,
                max_pages=max_pages,
                timeout=timeout,
            )
        )

    transactions = _normalize_transfers(
        transfers,
        address=normalized_address,
    )

    return AlchemyTransactionHistory(
        transactions=tuple(transactions),
        available=True,
    )


# ============================================================================
# TRANSFER RETRIEVAL
# ============================================================================


def _get_directional_transfers(
    *,
    rpc_url: str,
    address: str,
    direction: str,
    page_size: int,
    max_pages: int,
    timeout: int,
) -> list[dict[str, Any]]:
    """Retrieve paginated transfers for one address direction."""

    transfers: list[dict[str, Any]] = []
    page_key: str | None = None

    for _ in range(max_pages):
        params: dict[str, Any] = {
            "fromBlock": "0x0",
            "toBlock": "latest",
            direction: address,
            "category": [
                "external",
                "internal",
                "erc20",
                "erc721",
                "erc1155",
            ],
            "withMetadata": True,
            "excludeZeroValue": False,
            "maxCount": hex(page_size),
            "order": "desc",
        }

        if page_key:
            params["pageKey"] = page_key

        result = _rpc_call(
            rpc_url=rpc_url,
            params=[params],
            timeout=timeout,
        )

        if not isinstance(result, dict):
            raise AlchemyHistoryError(
                "Alchemy returned an invalid transfer response."
            )

        page_transfers = result.get("transfers", [])

        if isinstance(page_transfers, list):
            transfers.extend(
                item
                for item in page_transfers
                if isinstance(item, dict)
            )

        page_key = result.get("pageKey")

        if not isinstance(page_key, str) or not page_key:
            break

    return transfers


# ============================================================================
# NORMALIZATION
# ============================================================================


def _normalize_transfers(
    transfers: list[dict[str, Any]],
    *,
    address: str,
) -> list[AlchemyTransaction]:
    """Normalize and deduplicate public transfer records."""

    normalized: list[AlchemyTransaction] = []
    seen: set[str] = set()

    for transfer in transfers:
        transaction_hash = transfer.get("hash")

        if not isinstance(transaction_hash, str):
            continue

        transaction_hash = transaction_hash.strip().lower()

        if not _is_valid_transaction_hash(transaction_hash):
            continue

        # Alchemy can return multiple transfer records for one transaction.
        # uniqueId differentiates individual transfer events.
        unique_id = transfer.get("uniqueId")

        if isinstance(unique_id, str) and unique_id:
            dedupe_key = unique_id.lower()
        else:
            dedupe_key = transaction_hash

        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)

        from_address = _normalize_address_candidate(
            transfer.get("from")
        )

        to_address = _normalize_address_candidate(
            transfer.get("to")
        )

        if address == from_address:
            transaction_type = "outgoing"
        elif address == to_address:
            transaction_type = "incoming"
        else:
            transaction_type = "transfer"

        category = str(
            transfer.get("category") or ""
        ).lower()

        if category in {"erc20", "erc721", "erc1155"}:
            transaction_type = category

        amount = _safe_decimal(
            transfer.get("value")
        )

        symbol = transfer.get("asset")

        if not isinstance(symbol, str) or not symbol.strip():
            symbol = ETHEREUM_SYMBOL if category in {
                "external",
                "internal",
            } else None

        block_number = _parse_hex_int(
            transfer.get("blockNum")
        )

        timestamp = _parse_timestamp(
            transfer
        )

        normalized.append(
            AlchemyTransaction(
                transaction_hash=transaction_hash,
                transaction_type=transaction_type,
                status="confirmed",
                network=ETHEREUM_NETWORK_NAME,
                amount=amount,
                symbol=symbol.strip() if isinstance(symbol, str) else None,
                block_number=block_number,
                timestamp=timestamp,
            )
        )

    normalized.sort(
        key=lambda transaction: (
            transaction.timestamp or 0,
            transaction.block_number or 0,
        ),
        reverse=True,
    )

    return normalized


def _parse_timestamp(
    transfer: dict[str, Any],
) -> int | None:
    """Convert Alchemy ISO timestamp to Unix timestamp."""

    metadata = transfer.get("metadata")

    if not isinstance(metadata, dict):
        return None

    timestamp = metadata.get("blockTimestamp")

    if not isinstance(timestamp, str):
        return None

    try:
        from datetime import datetime

        normalized = timestamp.replace(
            "Z",
            "+00:00",
        )

        return int(
            datetime.fromisoformat(
                normalized
            ).timestamp()
        )

    except (ValueError, TypeError):
        return None


# ============================================================================
# RPC
# ============================================================================


def _rpc_call(
    *,
    rpc_url: str,
    params: list[Any],
    timeout: int,
) -> Any:
    """Execute an Alchemy JSON-RPC request."""

    payload = {
        "jsonrpc": JSON_RPC_VERSION,
        "id": 1,
        "method": RPC_METHOD_ASSET_TRANSFERS,
        "params": params,
    }

    request_body = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")

    request = Request(
        rpc_url,
        data=request_body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "HappyWallet/1.0",
        },
        method="POST",
    )

    last_error: Exception | None = None

    for attempt in range(2):
        try:
            with urlopen(
                request,
                timeout=timeout,
            ) as response:
                raw_body = response.read()

            response_data = json.loads(
                raw_body.decode("utf-8")
            )

            if not isinstance(response_data, dict):
                raise AlchemyHistoryError(
                    "Alchemy returned an invalid JSON-RPC response."
                )

            if response_data.get("jsonrpc") != JSON_RPC_VERSION:
                raise AlchemyHistoryError(
                    "Alchemy returned an invalid JSON-RPC version."
                )

            if response_data.get("id") != 1:
                raise AlchemyHistoryError(
                    "Alchemy returned an invalid response identifier."
                )

            error = response_data.get("error")

            if error is not None:
                logger.warning(
                    "Alchemy transaction history RPC error.",
                    extra={
                        "error_code": (
                            error.get("code")
                            if isinstance(error, dict)
                            else None
                        )
                    },
                )

                raise AlchemyHistoryError(
                    "Alchemy transaction history request failed."
                )

            return response_data.get("result")

        except HTTPError as exc:
            last_error = exc

            if exc.code not in {
                408,
                425,
                429,
                500,
                502,
                503,
                504,
            }:
                raise AlchemyHistoryError(
                    "Alchemy transaction history request failed."
                ) from exc

        except (
            URLError,
            socket.timeout,
            TimeoutError,
            OSError,
        ) as exc:
            last_error = exc

        except json.JSONDecodeError as exc:
            raise AlchemyHistoryError(
                "Alchemy returned invalid JSON."
            ) from exc

        if attempt == 0:
            time.sleep(0.25)

    raise AlchemyHistoryError(
        "Alchemy transaction history connection failed."
    ) from last_error


# ============================================================================
# VALIDATION
# ============================================================================


def _normalize_address(address: str) -> str:
    if not isinstance(address, str):
        raise AlchemyHistoryError(
            "Ethereum wallet address must be a string."
        )

    address = address.strip().lower()

    if (
        len(address) != ETHEREUM_ADDRESS_LENGTH
        or not address.startswith("0x")
    ):
        raise AlchemyHistoryError(
            "Invalid Ethereum wallet address."
        )

    try:
        int(address[2:], 16)
    except ValueError as exc:
        raise AlchemyHistoryError(
            "Invalid Ethereum wallet address."
        ) from exc

    return address


def _normalize_address_candidate(value: Any) -> str:
    if not isinstance(value, str):
        return ""

    return value.strip().lower()


def _is_valid_transaction_hash(value: str) -> bool:
    if not isinstance(value, str):
        return False

    if len(value) != ETHEREUM_HASH_LENGTH:
        return False

    if not value.startswith("0x"):
        return False

    try:
        int(value[2:], 16)
    except ValueError:
        return False

    return True


def _parse_hex_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return None

    try:
        return int(value, 16)
    except ValueError:
        return None


def _safe_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        result = Decimal(str(value))
    except Exception:
        return None

    if not result.is_finite():
        return None

    return result


def _normalize_page_size(value: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_SIZE

    return max(1, min(value, MAX_PAGE_SIZE))


def _normalize_max_pages(value: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_PAGES

    return max(
        MIN_MAX_PAGES,
        min(value, MAX_MAX_PAGES),
    )


def _normalize_timeout(value: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS

    return max(
        MIN_TIMEOUT_SECONDS,
        min(value, MAX_TIMEOUT_SECONDS),
    )


def _validate_rpc_url(rpc_url: str) -> None:
    if not isinstance(rpc_url, str):
        raise AlchemyHistoryError(
            "Alchemy RPC URL must be a string."
        )

    parsed = urlparse(rpc_url.strip())

    if parsed.scheme not in {"http", "https"}:
        raise AlchemyHistoryError(
            "Alchemy RPC URL must use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise AlchemyHistoryError(
            "Alchemy RPC URL is invalid."
        )


__all__ = [
    "AlchemyHistoryError",
    "AlchemyTransaction",
    "AlchemyTransactionHistory",
    "get_transaction_history",
]