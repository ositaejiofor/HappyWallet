"""HappyWallet read-only TRON network adapter.

This module can retrieve public TRON blockchain data.  It never accesses
wallet secrets, constructs transactions, signs data, or broadcasts a
transaction.  ``TronBroadcaster`` exists only to fail closed when the central
broadcast service resolves the TRON network.
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Final
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from django.conf import settings


TRON_PRO_API_KEY_HEADER: Final = "TRON-PRO-API-KEY"
TRON_USER_AGENT: Final = "HappyWallet/1.0"
TRON_SUN_PER_TRX: Final = Decimal("1000000")

DEFAULT_TRON_RPC_URL: Final = "https://api.trongrid.io"
DEFAULT_TIMEOUT_SECONDS: Final = 10
DEFAULT_MAX_RETRIES: Final = 2
DEFAULT_RETRY_BACKOFF_SECONDS: Final = 0.25
MAX_RESPONSE_BYTES: Final = 5 * 1024 * 1024
DEFAULT_TRANSACTION_LIMIT: Final = 25
MAX_TRANSACTION_LIMIT: Final = 200
MAX_TOKEN_DECIMALS: Final = 36

RETRYABLE_HTTP_STATUS_CODES: Final[frozenset[int]] = frozenset(
    {408, 425, 429, 500, 502, 503, 504}
)

JSONDict = dict[str, Any]


class TronNetworkError(RuntimeError):
    """Base exception for TRON network failures."""


class TronConfigurationError(TronNetworkError):
    """Raised when TRON provider configuration is invalid."""


class TronTemporaryError(TronNetworkError):
    """Raised when a retryable provider failure is exhausted."""


class TronResponseError(TronNetworkError):
    """Raised when TronGrid returns malformed or rejected data."""


class TronBroadcastDisabledError(TronNetworkError):
    """Raised whenever TRON transaction broadcasting is attempted."""


@dataclass(frozen=True, slots=True)
class TronTransaction:
    """Normalized public TRX transfer returned by TronGrid."""

    transaction_hash: str
    transaction_type: str
    status: str
    network: str = "TRON Mainnet"
    amount: Decimal | None = None
    symbol: str = "TRX"
    block_number: int | None = None
    timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class TronTransactionHistory:
    """Immutable result for a successful public history request."""

    transactions: tuple[TronTransaction, ...]
    available: bool


class TronReadOnlyClient:
    """Small, bounded client for public TronGrid FullNode endpoints."""

    def __init__(
        self,
        *,
        rpc_url: str | None = None,
        api_key: str | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
        retry_backoff_seconds: float | None = None,
    ) -> None:
        configured_url = (
            rpc_url
            if rpc_url is not None
            else getattr(settings, "TRON_RPC_URL", DEFAULT_TRON_RPC_URL)
        )
        configured_key = (
            api_key
            if api_key is not None
            else getattr(settings, "TRON_API_KEY", "")
        )
        configured_timeout = (
            timeout
            if timeout is not None
            else getattr(
                settings,
                "TRON_RPC_TIMEOUT",
                DEFAULT_TIMEOUT_SECONDS,
            )
        )
        configured_retries = (
            max_retries
            if max_retries is not None
            else getattr(
                settings,
                "RPC_MAX_RETRIES",
                DEFAULT_MAX_RETRIES,
            )
        )
        configured_backoff = (
            retry_backoff_seconds
            if retry_backoff_seconds is not None
            else getattr(
                settings,
                "RPC_RETRY_BACKOFF_SECONDS",
                DEFAULT_RETRY_BACKOFF_SECONDS,
            )
        )

        self.rpc_url = self._validate_rpc_url(configured_url)
        self.api_key = str(configured_key or "").strip()
        self.timeout = self._bounded_int(configured_timeout, 1, 30)
        self.max_retries = self._bounded_int(configured_retries, 0, 5)
        self.retry_backoff_seconds = self._bounded_float(
            configured_backoff,
            0.0,
            10.0,
        )

    def get_now_block(self) -> JSONDict:
        """Return the latest public TRON block."""

        payload = self._post("/wallet/getnowblock", {})

        if not isinstance(payload.get("blockID"), str):
            raise TronResponseError(
                "TRON provider returned an invalid latest block."
            )

        header = payload.get("block_header")
        if not isinstance(header, dict):
            raise TronResponseError(
                "TRON provider returned an invalid block header."
            )

        return payload

    def get_account(self, address: str) -> JSONDict:
        """Return public account data for a TRON base58 or hex address."""

        normalized_address, visible = self._prepare_address(address)
        payload = self._post(
            "/wallet/getaccount",
            {
                "address": normalized_address,
                "visible": visible,
            },
        )

        if not isinstance(payload, dict):
            raise TronResponseError(
                "TRON provider returned invalid account data."
            )

        return payload

    def get_trx_balance(self, address: str) -> Decimal:
        """Return the public native TRX balance in TRX, not sun."""

        account = self.get_account(address)
        raw_balance = account.get("balance", 0)

        if isinstance(raw_balance, bool) or not isinstance(
            raw_balance,
            (int, str),
        ):
            raise TronResponseError(
                "TRON provider returned an invalid account balance."
            )

        try:
            balance_sun = Decimal(str(raw_balance))
        except InvalidOperation as exc:
            raise TronResponseError(
                "TRON provider returned an invalid account balance."
            ) from exc

        if not balance_sun.is_finite() or balance_sun < 0:
            raise TronResponseError(
                "TRON provider returned an invalid account balance."
            )

        return balance_sun / TRON_SUN_PER_TRX

    def get_trc20_balance(
        self,
        address: str,
        *,
        contract_address: str,
        decimals: int,
    ) -> Decimal:
        """Return a confirmed public TRC-20 balance in token units."""

        normalized_address, _visible = self._prepare_address(address)
        normalized_contract, _contract_visible = self._prepare_address(
            contract_address
        )
        token_decimals = self._bounded_token_decimals(decimals)
        query = urlencode({"only_confirmed": "true"})
        payload = self._get(
            f"/v1/accounts/{quote(normalized_address, safe='')}?{query}"
        )

        if payload.get("success") is not True:
            raise TronResponseError(
                "TRON provider rejected the account request."
            )

        accounts = payload.get("data")
        if not isinstance(accounts, list):
            raise TronResponseError(
                "TRON provider returned invalid account data."
            )
        if not accounts:
            return Decimal("0")

        account = accounts[0]
        if not isinstance(account, dict):
            raise TronResponseError(
                "TRON provider returned invalid account data."
            )

        token_entries = account.get("trc20", [])
        if not isinstance(token_entries, list):
            raise TronResponseError(
                "TRON provider returned invalid TRC-20 balances."
            )

        raw_balance = Decimal("0")
        for entry in token_entries:
            if not isinstance(entry, dict):
                raise TronResponseError(
                    "TRON provider returned invalid TRC-20 balances."
                )
            for token_address, value in entry.items():
                if token_address != normalized_contract:
                    continue
                if isinstance(value, bool):
                    raise TronResponseError(
                        "TRON provider returned an invalid TRC-20 balance."
                    )
                try:
                    raw_balance = Decimal(str(value))
                except (InvalidOperation, TypeError, ValueError) as exc:
                    raise TronResponseError(
                        "TRON provider returned an invalid TRC-20 balance."
                    ) from exc

        if not raw_balance.is_finite() or raw_balance < 0:
            raise TronResponseError(
                "TRON provider returned an invalid TRC-20 balance."
            )

        return raw_balance / (Decimal(10) ** token_decimals)

    def get_transaction_history(
        self,
        address: str,
        *,
        limit: int = DEFAULT_TRANSACTION_LIMIT,
    ) -> TronTransactionHistory:
        """Return confirmed public TRX transfers, newest first."""

        normalized_address, _visible = self._prepare_address(address)
        bounded_limit = self._bounded_int(
            limit,
            1,
            MAX_TRANSACTION_LIMIT,
        )
        query = urlencode(
            {
                "only_confirmed": "true",
                "limit": bounded_limit,
                "order_by": "block_timestamp,desc",
            }
        )
        payload = self._get(
            f"/v1/accounts/{quote(normalized_address, safe='')}/transactions?{query}"
        )

        if payload.get("success") is not True:
            raise TronResponseError(
                "TRON provider rejected the history request."
            )

        raw_transactions = payload.get("data")
        if not isinstance(raw_transactions, list):
            raise TronResponseError(
                "TRON provider returned invalid transaction history."
            )

        transactions: list[TronTransaction] = []

        for raw_transaction in raw_transactions:
            transaction = self._parse_trx_transfer(raw_transaction)
            if transaction is not None:
                transactions.append(transaction)

        return TronTransactionHistory(
            transactions=tuple(transactions),
            available=True,
        )

    def get_trc20_transaction_history(
        self,
        address: str,
        *,
        contract_address: str,
        symbol: str = "USDT",
        decimals: int = 6,
        limit: int = DEFAULT_TRANSACTION_LIMIT,
    ) -> TronTransactionHistory:
        """Return confirmed transfers for one configured TRC-20 token."""

        normalized_address, _visible = self._prepare_address(address)
        normalized_contract, _contract_visible = self._prepare_address(
            contract_address
        )
        token_decimals = self._bounded_token_decimals(decimals)
        bounded_limit = self._bounded_int(limit, 1, MAX_TRANSACTION_LIMIT)
        normalized_symbol = str(symbol or "").strip().upper()
        if not normalized_symbol:
            raise TronNetworkError("TRC-20 token symbol is required.")

        query = urlencode(
            {
                "only_confirmed": "true",
                "limit": bounded_limit,
                "order_by": "block_timestamp,desc",
                "contract_address": normalized_contract,
            }
        )
        payload = self._get(
            f"/v1/accounts/{quote(normalized_address, safe='')}"
            f"/transactions/trc20?{query}"
        )

        if payload.get("success") is not True:
            raise TronResponseError(
                "TRON provider rejected the TRC-20 history request."
            )
        raw_transactions = payload.get("data")
        if not isinstance(raw_transactions, list):
            raise TronResponseError(
                "TRON provider returned invalid TRC-20 history."
            )

        transactions = []
        for raw_transaction in raw_transactions:
            transaction = self._parse_trc20_transfer(
                raw_transaction,
                wallet_address=normalized_address,
                contract_address=normalized_contract,
                symbol=normalized_symbol,
                decimals=token_decimals,
            )
            if transaction is not None:
                transactions.append(transaction)

        return TronTransactionHistory(
            transactions=tuple(transactions),
            available=True,
        )

    def _get(self, path: str) -> JSONDict:
        return self._request(
            Request(
                f"{self.rpc_url}{path}",
                headers=self._headers(),
                method="GET",
            )
        )

    def _post(self, path: str, payload: JSONDict) -> JSONDict:
        request_body = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")

        return self._request(
            Request(
                f"{self.rpc_url}{path}",
                data=request_body,
                headers=self._headers(),
                method="POST",
            )
        )

    def _request(self, request: Request) -> JSONDict:

        attempts = self.max_retries + 1
        last_error: BaseException | None = None

        for attempt in range(attempts):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    status = getattr(response, "status", 200)

                    if not 200 <= int(status) < 300:
                        raise TronResponseError(
                            "TRON provider rejected the request."
                        )

                    raw_data = response.read(MAX_RESPONSE_BYTES + 1)

                if len(raw_data) > MAX_RESPONSE_BYTES:
                    raise TronResponseError(
                        "TRON provider response is too large."
                    )

                try:
                    decoded = json.loads(raw_data.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise TronResponseError(
                        "TRON provider returned invalid JSON."
                    ) from exc

                if not isinstance(decoded, dict):
                    raise TronResponseError(
                        "TRON provider returned an invalid response."
                    )

                return decoded

            except HTTPError as exc:
                if exc.code not in RETRYABLE_HTTP_STATUS_CODES:
                    raise TronResponseError(
                        "TRON provider rejected the request."
                    ) from exc
                last_error = exc

            except (URLError, TimeoutError, socket.timeout) as exc:
                last_error = exc

            if attempt + 1 < attempts:
                delay = self.retry_backoff_seconds * (2**attempt)
                if delay:
                    time.sleep(delay)

        raise TronTemporaryError(
            "TRON provider is temporarily unavailable."
        ) from last_error

    @staticmethod
    def _parse_trx_transfer(payload: Any) -> TronTransaction | None:
        if not isinstance(payload, dict):
            return None

        transaction_hash = payload.get("txID")
        raw_data = payload.get("raw_data")

        if not isinstance(transaction_hash, str) or not transaction_hash:
            return None
        if not isinstance(raw_data, dict):
            return None

        contracts = raw_data.get("contract")
        if not isinstance(contracts, list) or not contracts:
            return None

        contract = contracts[0]
        if not isinstance(contract, dict):
            return None
        if contract.get("type") != "TransferContract":
            return None

        parameter = contract.get("parameter")
        value = parameter.get("value") if isinstance(parameter, dict) else None
        if not isinstance(value, dict):
            return None

        raw_amount = value.get("amount")
        if isinstance(raw_amount, bool):
            return None

        try:
            amount_sun = Decimal(str(raw_amount))
        except (InvalidOperation, TypeError, ValueError):
            return None

        if not amount_sun.is_finite() or amount_sun < 0:
            return None

        ret = payload.get("ret")
        result = ret[0].get("contractRet") if (
            isinstance(ret, list)
            and ret
            and isinstance(ret[0], dict)
        ) else None
        status = "confirmed" if result == "SUCCESS" else "failed"

        block_number = payload.get("blockNumber")
        if isinstance(block_number, bool) or not isinstance(block_number, int):
            block_number = None

        timestamp_ms = payload.get("block_timestamp")
        timestamp = (
            timestamp_ms // 1000
            if isinstance(timestamp_ms, int)
            and not isinstance(timestamp_ms, bool)
            and timestamp_ms >= 0
            else None
        )

        return TronTransaction(
            transaction_hash=transaction_hash,
            transaction_type="transfer",
            status=status,
            amount=amount_sun / TRON_SUN_PER_TRX,
            block_number=block_number,
            timestamp=timestamp,
        )

    @staticmethod
    def _parse_trc20_transfer(
        payload: Any,
        *,
        wallet_address: str,
        contract_address: str,
        symbol: str,
        decimals: int,
    ) -> TronTransaction | None:
        if not isinstance(payload, dict):
            return None

        transaction_hash = payload.get("transaction_id")
        token_info = payload.get("token_info")
        if not isinstance(transaction_hash, str) or not transaction_hash:
            return None
        if not isinstance(token_info, dict):
            return None
        if token_info.get("address") != contract_address:
            return None

        sender = payload.get("from")
        recipient = payload.get("to")
        if recipient == wallet_address:
            transaction_type = "receive"
        elif sender == wallet_address:
            transaction_type = "send"
        else:
            return None

        raw_value = payload.get("value")
        if isinstance(raw_value, bool):
            return None
        try:
            value = Decimal(str(raw_value))
        except (InvalidOperation, TypeError, ValueError):
            return None
        if not value.is_finite() or value < 0:
            return None

        timestamp_ms = payload.get("block_timestamp")
        timestamp = (
            timestamp_ms // 1000
            if isinstance(timestamp_ms, int)
            and not isinstance(timestamp_ms, bool)
            and timestamp_ms >= 0
            else None
        )

        return TronTransaction(
            transaction_hash=transaction_hash,
            transaction_type=transaction_type,
            status="confirmed",
            amount=value / (Decimal(10) ** decimals),
            symbol=symbol,
            timestamp=timestamp,
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": TRON_USER_AGENT,
        }

        if self.api_key:
            headers[TRON_PRO_API_KEY_HEADER] = self.api_key

        return headers

    @staticmethod
    def _prepare_address(address: str) -> tuple[str, bool]:
        if not isinstance(address, str):
            raise TronNetworkError("TRON address must be a string.")

        normalized = address.strip()

        if len(normalized) == 34 and normalized.startswith("T"):
            return normalized, True

        if (
            len(normalized) == 42
            and normalized.startswith("41")
            and all(character in "0123456789abcdefABCDEF" for character in normalized)
        ):
            return normalized, False

        raise TronNetworkError("TRON address is invalid.")

    @staticmethod
    def _validate_rpc_url(rpc_url: object) -> str:
        if not isinstance(rpc_url, str):
            raise TronConfigurationError("TRON RPC URL must be a string.")

        normalized = rpc_url.strip().rstrip("/")
        parsed = urlparse(normalized)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise TronConfigurationError("TRON RPC URL is invalid.")

        return normalized

    @staticmethod
    def _bounded_int(value: object, minimum: int, maximum: int) -> int:
        try:
            normalized = int(value)
        except (TypeError, ValueError):
            normalized = minimum
        return max(minimum, min(normalized, maximum))

    @staticmethod
    def _bounded_float(
        value: object,
        minimum: float,
        maximum: float,
    ) -> float:
        try:
            normalized = float(value)
        except (TypeError, ValueError):
            normalized = minimum
        return max(minimum, min(normalized, maximum))

    @staticmethod
    def _bounded_token_decimals(value: object) -> int:
        if isinstance(value, bool):
            raise TronNetworkError("TRC-20 token decimals are invalid.")
        try:
            decimals = int(value)
        except (TypeError, ValueError) as exc:
            raise TronNetworkError("TRC-20 token decimals are invalid.") from exc
        if not 0 <= decimals <= MAX_TOKEN_DECIMALS:
            raise TronNetworkError("TRC-20 token decimals are invalid.")
        return decimals


class TronBroadcaster:
    """Fail-closed broadcaster required by the central network resolver."""

    @staticmethod
    def broadcast(*, raw_transaction: bytes) -> str:
        del raw_transaction

        # Imported lazily to avoid a module-import cycle.  This exception is
        # already part of TransactionBroadcaster's public error contract.
        from apps.transaction.services.broadcaster import (
            BroadcastRejectedError,
        )

        raise BroadcastRejectedError(
            "TRON transaction broadcasting is disabled by HappyWallet policy."
        )


__all__ = [
    "TronBroadcastDisabledError",
    "TronBroadcaster",
    "TronConfigurationError",
    "TronNetworkError",
    "TronReadOnlyClient",
    "TronResponseError",
    "TronTemporaryError",
    "TronTransaction",
    "TronTransactionHistory",
]
