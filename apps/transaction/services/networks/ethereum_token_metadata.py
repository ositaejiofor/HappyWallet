"""
HappyWallet Ethereum ERC-20 Token Metadata Service.

Read-only ERC-20 metadata discovery.

Security boundary
-----------------

This module MUST NEVER:

    - access private keys
    - access wallet mnemonics
    - decrypt wallet secrets
    - sign transactions
    - broadcast transactions
    - approve token spending
    - transfer tokens
    - modify wallet records
    - persist token metadata
    - expose RPC credentials

Only public contract data is accessed.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from dataclasses import dataclass
from http.client import IncompleteRead, RemoteDisconnected
from typing import Any
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
# CONSTANTS
# ============================================================================

ETHEREUM_HEX_PREFIX = "0x"
ETHEREUM_ADDRESS_LENGTH = 42
ETHEREUM_HASH_LENGTH = 66

JSON_RPC_VERSION = "2.0"
JSON_RPC_REQUEST_ID = 1

RPC_METHOD_ETH_CALL = "eth_call"

DEFAULT_TIMEOUT_SECONDS = 10
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 30

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


# ERC-20 function selectors.
#
# keccak256("name()")[:4]      = 06fdde03
# keccak256("symbol()")[:4]    = 95d89b41
# keccak256("decimals()")[:4]  = 313ce567

ERC20_NAME_SELECTOR = "0x06fdde03"
ERC20_SYMBOL_SELECTOR = "0x95d89b41"
ERC20_DECIMALS_SELECTOR = "0x313ce567"


# ============================================================================
# EXCEPTIONS
# ============================================================================


class EthereumTokenMetadataError(RuntimeError):
    """Base exception for ERC-20 metadata failures."""


class EthereumTokenMetadataTemporaryError(
    EthereumTokenMetadataError,
):
    """Raised when an RPC failure appears temporary."""


# ============================================================================
# RESULT TYPE
# ============================================================================


@dataclass(frozen=True, slots=True)
class ERC20TokenMetadata:
    """
    Immutable ERC-20 token metadata.

    All fields originate from public contract reads.
    """

    token_address: str
    name: str | None
    symbol: str | None
    decimals: int | None


# ============================================================================
# PUBLIC API
# ============================================================================


def get_token_metadata(
    *,
    rpc_url: str,
    token_address: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> ERC20TokenMetadata:
    """
    Retrieve ERC-20 metadata using eth_call.

    This function performs read-only blockchain calls.

    It does not sign, broadcast, approve, transfer, or persist anything.
    """

    normalized_rpc_url = _validate_rpc_url(
        rpc_url,
    )

    normalized_token = _normalize_token_address(
        token_address,
    )

    normalized_timeout = _normalize_timeout(
        timeout,
    )

    name = _get_text_metadata(
        rpc_url=normalized_rpc_url,
        token_address=normalized_token,
        selector=ERC20_NAME_SELECTOR,
        field_name="name",
        timeout=normalized_timeout,
    )

    symbol = _get_text_metadata(
        rpc_url=normalized_rpc_url,
        token_address=normalized_token,
        selector=ERC20_SYMBOL_SELECTOR,
        field_name="symbol",
        timeout=normalized_timeout,
    )

    decimals = _get_decimals(
        rpc_url=normalized_rpc_url,
        token_address=normalized_token,
        timeout=normalized_timeout,
    )

    return ERC20TokenMetadata(
        token_address=normalized_token,
        name=name,
        symbol=symbol,
        decimals=decimals,
    )


# ============================================================================
# ERC-20 READS
# ============================================================================


def _get_text_metadata(
    *,
    rpc_url: str,
    token_address: str,
    selector: str,
    field_name: str,
    timeout: int,
) -> str | None:
    """
    Read a string-returning ERC-20 function.

    Supports standard ABI dynamic-string encoding.
    """

    result = _eth_call(
        rpc_url=rpc_url,
        token_address=token_address,
        data=selector,
        timeout=timeout,
    )

    return _decode_abi_string(
        result,
        field_name=field_name,
    )


def _get_decimals(
    *,
    rpc_url: str,
    token_address: str,
    timeout: int,
) -> int | None:
    """Read ERC-20 decimals()."""

    result = _eth_call(
        rpc_url=rpc_url,
        token_address=token_address,
        data=ERC20_DECIMALS_SELECTOR,
        timeout=timeout,
    )

    if not isinstance(result, str):
        return None

    normalized = result.strip().lower()

    if not normalized.startswith(
        ETHEREUM_HEX_PREFIX,
    ):
        return None

    payload = normalized[2:]

    if not payload:
        return None

    if len(payload) > 64:
        return None

    try:
        value = int(
            payload,
            16,
        )
    except ValueError:
        return None

    if value < 0 or value > 255:
        return None

    return value


# ============================================================================
# ETH_CALL
# ============================================================================


def _eth_call(
    *,
    rpc_url: str,
    token_address: str,
    data: str,
    timeout: int,
) -> Any:
    """Execute a read-only eth_call against an ERC-20 contract."""

    call_object = {
        "to": token_address,
        "data": data,
    }

    return _rpc_call(
        rpc_url=rpc_url,
        method=RPC_METHOD_ETH_CALL,
        params=[
            call_object,
            "latest",
        ],
        timeout=timeout,
    )


def _rpc_call(
    *,
    rpc_url: str,
    method: str,
    params: list[Any],
    timeout: int,
) -> Any:
    """Execute one bounded JSON-RPC request."""

    payload: JSONDict = {
        "jsonrpc": JSON_RPC_VERSION,
        "id": JSON_RPC_REQUEST_ID,
        "method": method,
        "params": params,
    }

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
                "User-Agent": "HappyWallet/1.0",
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
                raise EthereumTokenMetadataError(
                    "Ethereum RPC returned an unexpected HTTP status."
                )

            return _decode_rpc_response(
                raw_body,
            )

        except HTTPError as exc:
            last_error = exc

            if exc.code not in RETRYABLE_HTTP_STATUS_CODES:
                logger.warning(
                    "Ethereum token metadata RPC HTTP request failed.",
                    extra={
                        "method": method,
                        "status_code": exc.code,
                    },
                )

                raise EthereumTokenMetadataError(
                    "Ethereum RPC HTTP request failed."
                ) from exc

            logger.warning(
                "Transient Ethereum token metadata RPC failure.",
                extra={
                    "method": method,
                    "status_code": exc.code,
                    "attempt": attempt + 1,
                },
            )

        except (
            IncompleteRead,
            RemoteDisconnected,
            ConnectionResetError,
            BrokenPipeError,
            URLError,
            socket.timeout,
            TimeoutError,
            OSError,
        ) as exc:
            last_error = exc

            logger.warning(
                "Ethereum token metadata RPC transport failure.",
                extra={
                    "method": method,
                    "error_type": type(exc).__name__,
                    "attempt": attempt + 1,
                },
            )

        if attempt + 1 < attempts:
            _sleep_before_retry(
                attempt=attempt,
            )

    raise EthereumTokenMetadataTemporaryError(
        "Ethereum RPC connection failed."
    ) from last_error


# ============================================================================
# RESPONSE DECODING
# ============================================================================


def _decode_rpc_response(
    raw_body: bytes,
) -> Any:
    """Decode a JSON-RPC response without exposing response credentials."""

    try:
        response_data = json.loads(
            raw_body.decode("utf-8"),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise EthereumTokenMetadataError(
            "Ethereum RPC returned invalid JSON."
        ) from exc

    if not isinstance(
        response_data,
        dict,
    ):
        raise EthereumTokenMetadataError(
            "Ethereum RPC returned an invalid response."
        )

    if response_data.get(
        "jsonrpc",
    ) != JSON_RPC_VERSION:
        raise EthereumTokenMetadataError(
            "Ethereum RPC returned an invalid protocol version."
        )

    if response_data.get(
        "id",
    ) != JSON_RPC_REQUEST_ID:
        raise EthereumTokenMetadataError(
            "Ethereum RPC returned an invalid response identifier."
        )

    if response_data.get("error") is not None:
        logger.warning(
            "Ethereum RPC provider returned an error.",
            extra={
                "method": RPC_METHOD_ETH_CALL,
            },
        )

        raise EthereumTokenMetadataError(
            "Ethereum RPC returned an error."
        )

    if "result" not in response_data:
        raise EthereumTokenMetadataError(
            "Ethereum RPC response contained no result."
        )

    return response_data["result"]


# ============================================================================
# ABI DECODING
# ============================================================================


def _decode_abi_string(
    value: Any,
    *,
    field_name: str,
) -> str | None:
    """
    Decode an ABI dynamic string.

    Expected layout:

        offset
        length
        UTF-8 bytes
    """

    if not isinstance(
        value,
        str,
    ):
        return None

    normalized = value.strip().lower()

    if not normalized.startswith(
        ETHEREUM_HEX_PREFIX,
    ):
        return None

    payload = normalized[2:]

    if not payload:
        return None

    if len(payload) % 2 != 0:
        return None

    if not _is_hex_payload(payload):
        return None

    if len(payload) < 128:
        return None

    try:
        offset = int(
            payload[:64],
            16,
        )

        if offset % 32 != 0:
            return None

        offset_hex_index = offset * 2

        if offset_hex_index + 64 > len(payload):
            return None

        length = int(
            payload[
                offset_hex_index:
                offset_hex_index + 64
            ],
            16,
        )

        data_start = (
            offset_hex_index + 64
        )

        data_end = (
            data_start + (length * 2)
        )

        if data_end > len(payload):
            return None

        raw_text = bytes.fromhex(
            payload[data_start:data_end],
        )

        decoded = raw_text.decode(
            "utf-8",
        ).strip()

    except (
        ValueError,
        UnicodeDecodeError,
    ):
        logger.debug(
            "Unable to decode ERC-20 token metadata.",
            extra={
                "field": field_name,
            },
        )
        return None

    return decoded or None


# ============================================================================
# VALIDATION
# ============================================================================


def _normalize_token_address(
    value: str,
) -> str:
    """Normalize and validate an ERC-20 contract address."""

    if not isinstance(
        value,
        str,
    ):
        raise EthereumTokenMetadataError(
            "Token address must be a string."
        )

    normalized = _normalize_address_candidate(
        value,
    )

    if not normalized:
        raise EthereumTokenMetadataError(
            "Invalid ERC-20 token address."
        )

    if len(normalized) != ETHEREUM_ADDRESS_LENGTH:
        raise EthereumTokenMetadataError(
            "Invalid ERC-20 token address."
        )

    return normalized.lower()


def _validate_rpc_url(
    rpc_url: str,
) -> str:
    """Validate an HTTP(S) Ethereum RPC URL."""

    if not isinstance(
        rpc_url,
        str,
    ):
        raise EthereumTokenMetadataError(
            "Ethereum RPC URL must be a string."
        )

    normalized = rpc_url.strip()

    if not normalized:
        raise EthereumTokenMetadataError(
            "Ethereum RPC URL is not configured."
        )

    parsed = urlparse(
        normalized,
    )

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise EthereumTokenMetadataError(
            "Ethereum RPC URL must use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise EthereumTokenMetadataError(
            "Ethereum RPC URL is invalid."
        )

    return normalized


def _normalize_timeout(
    value: int,
) -> int:
    """Normalize RPC timeout."""

    if isinstance(
        value,
        bool,
    ) or not isinstance(
        value,
        int,
    ):
        raise EthereumTokenMetadataError(
            "Invalid Ethereum RPC timeout."
        )

    if value < MIN_TIMEOUT_SECONDS:
        raise EthereumTokenMetadataError(
            "Ethereum RPC timeout is too small."
        )

    return min(
        value,
        MAX_TIMEOUT_SECONDS,
    )


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
        DEFAULT_RETRY_BACKOFF_SECONDS
        * (2**attempt),
        MAX_RETRY_BACKOFF_SECONDS,
    )

    time.sleep(
        delay,
    )


# ============================================================================
# HEX HELPERS
# ============================================================================


def _is_hex_payload(
    value: str,
) -> bool:
    """Return True when a string contains hexadecimal characters only."""

    if not isinstance(
        value,
        str,
    ):
        return False

    if not value:
        return False

    try:
        int(
            value,
            16,
        )
    except ValueError:
        return False

    return True


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================


__all__ = [
    "ERC20TokenMetadata",
    "EthereumTokenMetadataError",
    "EthereumTokenMetadataTemporaryError",
    "get_token_metadata",
    "ERC20_NAME_SELECTOR",
    "ERC20_SYMBOL_SELECTOR",
    "ERC20_DECIMALS_SELECTOR",
]