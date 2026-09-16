"""
HappyWallet Kraken trading adapter.

This module is the isolated boundary between HappyWallet's trading
system and the Kraken Spot API.

Safety rules
------------
- API credentials come only from Django settings or explicit constructor
  injection used by tests.
- Credentials are never logged or returned to callers.
- Live trading is disabled unless explicitly enabled.
- Real order submission is NOT implemented yet.
- Wallet private keys, seed phrases, mnemonics, and signing material
  are never accessed.
- Public and authenticated API requests are handled separately.
- Live order submission must remain behind LiveExecutionService.
"""

import base64
import hashlib
import hmac
import time
import urllib.parse

import requests
from django.conf import settings


class KrakenError(Exception):
    """Base exception for Kraken API failures."""


class KrakenConfigurationError(KrakenError):
    """Raised when Kraken credentials or configuration are invalid."""


class KrakenAPIError(KrakenError):
    """Base class for Kraken API request failures."""


class KrakenTransportError(KrakenAPIError):
    """
    Raised when Kraken submission outcome may be uncertain.

    Examples:
        - network failure
        - timeout
        - HTTP failure after request transmission
        - invalid response JSON

    A caller must NOT blindly retry a live order after this error.
    Reconciliation should be attempted first.
    """


class KrakenRejectedError(KrakenAPIError):
    """
    Raised when Kraken explicitly returned an API error.

    This represents a definite exchange rejection rather than an
    ambiguous transport outcome.
    """


class KrakenAdapter:
    """
    Conservative Kraken Spot API adapter.

    Public operations
    ------------------
    - get_server_time()
    - get_asset_pairs()
    - get_ticker()

    Authenticated read-only operations
    ----------------------------------
    - get_account_balance()
    - get_open_orders()
    - get_closed_orders()

    Safety
    ------
    - assert_live_trading_enabled()

    Live execution
    --------------
    Real order submission is intentionally not implemented.

    Real orders must eventually pass through LiveExecutionService,
    which provides the application-level validation, confirmation,
    and risk boundary.
    """

    BASE_URL = "https://api.kraken.com"
    API_VERSION = "0"

    def __init__(
        self,
        *,
        api_key=None,
        api_secret=None,
        timeout=10,
        live_trading_enabled=None,
        session=None,
    ):
        """
        Initialize the Kraken adapter.

        Credentials default to Django settings.

        Explicit credentials are supported for tests so fake credentials
        can be supplied without modifying environment variables.
        """

        self.api_key = (
            api_key
            if api_key is not None
            else getattr(
                settings,
                "KRAKEN_API_KEY",
                "",
            )
        )

        self.api_secret = (
            api_secret
            if api_secret is not None
            else getattr(
                settings,
                "KRAKEN_API_SECRET",
                "",
            )
        )

        self.timeout = timeout

        if live_trading_enabled is None:
            live_trading_enabled = getattr(
                settings,
                "KRAKEN_LIVE_TRADING_ENABLED",
                False,
            )

        self.live_trading_enabled = bool(
            live_trading_enabled
        )

        self.session = session or requests.Session()

        # Kraken requires authenticated request nonces to increase.
        # The counter guarantees uniqueness for requests created within
        # the same millisecond.
        self._last_nonce = 0

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @property
    def is_configured(self):
        """
        Return True when both Kraken credentials are configured.
        """

        return bool(
            self.api_key
            and self.api_secret
        )

    def validate_configuration(self):
        """
        Validate Kraken credentials.

        Credential values are intentionally never included in errors.
        """

        if not self.api_key:
            raise KrakenConfigurationError(
                "KRAKEN_API_KEY is not configured."
            )

        if not self.api_secret:
            raise KrakenConfigurationError(
                "KRAKEN_API_SECRET is not configured."
            )

    # ------------------------------------------------------------------
    # Nonce
    # ------------------------------------------------------------------

    def _nonce(self):
        """
        Return a strictly increasing Kraken nonce.

        Millisecond precision is sufficient for this adapter.

        The in-process counter guarantees that multiple requests created
        during the same millisecond still receive unique nonce values.

        Returns:
            str: Strictly increasing integer nonce.
        """

        now = int(
            time.time() * 1000
        )

        nonce = max(
            now,
            self._last_nonce + 1,
        )

        self._last_nonce = nonce

        return str(nonce)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _signature(
        self,
        path,
        data,
    ):
        """
        Create Kraken's API-Sign value.

        Kraken signs:

            path + SHA256(nonce + POST data)

        using the base64-decoded API secret and HMAC-SHA512.

        Args:
            path: Kraken API path.
            data: POST payload containing a nonce.

        Returns:
            str: Base64-encoded API signature.
        """

        nonce = data.get("nonce")

        if nonce is None:
            raise KrakenConfigurationError(
                "Authenticated Kraken requests require a nonce."
            )

        try:
            secret = base64.b64decode(
                self.api_secret,
                validate=True,
            )
        except (ValueError, TypeError):
            raise KrakenConfigurationError(
                "KRAKEN_API_SECRET is not valid base64."
            )

        post_data = urllib.parse.urlencode(
            data,
        )

        encoded = (
            str(nonce)
            + post_data
        ).encode()

        sha256_digest = hashlib.sha256(
            encoded,
        ).digest()

        message = (
            path.encode()
            + sha256_digest
        )

        signature = hmac.new(
            secret,
            message,
            hashlib.sha512,
        ).digest()

        return base64.b64encode(
            signature,
        ).decode()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _public_request(
        self,
        endpoint,
        params=None,
    ):
        """
        Execute a Kraken public API request.

        Public endpoints do not require API credentials.

        Args:
            endpoint: Kraken public endpoint name.
            params: Optional query-string parameters.

        Returns:
            dict: Kraken result payload.

        Raises:
            KrakenAPIError: On network, HTTP, JSON, or API errors.
        """

        path = (
            f"/{self.API_VERSION}"
            f"/public/{endpoint}"
        )

        url = (
            f"{self.BASE_URL}"
            f"{path}"
        )

        try:
            response = self.session.get(
                url,
                params=params or {},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise KrakenTransportError(
                f"Kraken request failed: {exc}"
            ) from exc

        if not response.ok:
            raise KrakenTransportError(
                "Kraken returned HTTP "
                f"{response.status_code}."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise KrakenTransportError(
                "Kraken returned invalid JSON."
            ) from exc

        errors = body.get("error") or []

        if errors:
            raise KrakenRejectedError(
                "Kraken API returned an error: "
                + ", ".join(
                    str(error)
                    for error in errors
                )
            )

        return body.get(
            "result",
            {},
        )

    def get_server_time(self):
        """
        Retrieve Kraken server time.

        Returns:
            dict: Kraken server-time result.
        """

        return self._public_request(
            "Time",
        )

    def get_asset_pairs(
        self,
        pair=None,
    ):
        """
        Retrieve Kraken's available trading pairs.

        Args:
            pair: Optional Kraken pair identifier.

        Returns:
            dict: Kraken asset-pair information.
        """

        params = {}

        if pair:
            params["pair"] = pair

        return self._public_request(
            "AssetPairs",
            params=params,
        )

    def get_ticker(
        self,
        pair,
    ):
        """
        Retrieve current Kraken ticker information.

        Args:
            pair: Kraken trading-pair identifier.

        Returns:
            dict: Kraken ticker information.

        Raises:
            ValueError: If no pair is supplied.
        """

        if not pair:
            raise ValueError(
                "A Kraken trading pair is required."
            )

        return self._public_request(
            "Ticker",
            params={
                "pair": pair,
            },
        )

    # ------------------------------------------------------------------
    # Authenticated API
    # ------------------------------------------------------------------

    def _private_request(
        self,
        endpoint,
        data=None,
    ):
        """
        Execute an authenticated Kraken private API request.

        Args:
            endpoint: Kraken private endpoint name.
            data: Optional POST parameters.

        Returns:
            dict: Kraken result payload.

        Raises:
            KrakenConfigurationError: If credentials are missing/invalid.
            KrakenAPIError: On network, HTTP, JSON, or API errors.
        """

        self.validate_configuration()

        path = (
            f"/{self.API_VERSION}"
            f"/private/{endpoint}"
        )

        payload = dict(
            data or {}
        )

        payload.setdefault(
            "nonce",
            self._nonce(),
        )

        signature = self._signature(
            path,
            payload,
        )

        headers = {
            "API-Key": self.api_key,
            "API-Sign": signature,
        }

        url = (
            f"{self.BASE_URL}"
            f"{path}"
        )

        try:
            response = self.session.post(
                url,
                data=payload,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise KrakenTransportError(
                f"Kraken request failed: {exc}"
            ) from exc

        if not response.ok:
            raise KrakenTransportError(
                "Kraken returned HTTP "
                f"{response.status_code}."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise KrakenTransportError(
                "Kraken returned invalid JSON."
            ) from exc

        errors = body.get("error") or []

        if errors:
            raise KrakenRejectedError(
                "Kraken API returned an error: "
                + ", ".join(
                    str(error)
                    for error in errors
                )
            )

        return body.get(
            "result",
            {},
        )

    # ------------------------------------------------------------------
    # Account
    # ------------------------------------------------------------------

    def get_account_balance(self):
        """
        Retrieve balances from the authenticated Kraken account.

        This operation is read-only.

        Returns:
            dict: Kraken account balance result.
        """

        return self._private_request(
            "Balance",
        )

    def get_open_orders(
        self,
        *,
        trades=False,
    ):
        """
        Retrieve the authenticated user's open orders.

        This operation is read-only.

        Args:
            trades: Include trade information when True.

        Returns:
            dict: Kraken open-orders result.
        """

        return self._private_request(
            "OpenOrders",
            data={
                "trades": "true" if trades else "false",
            },
        )

    def get_closed_orders(
        self,
        *,
        trades=False,
        start=None,
        end=None,
    ):
        """
        Retrieve the authenticated user's closed orders.

        This operation is read-only.

        Args:
            trades: Include trade information when True.
            start: Optional starting timestamp.
            end: Optional ending timestamp.

        Returns:
            dict: Kraken closed-orders result.
        """

        data = {
            "trades": "true" if trades else "false",
        }

        if start is not None:
            data["start"] = start

        if end is not None:
            data["end"] = end

        return self._private_request(
            "ClosedOrders",
            data=data,
        )

    # ------------------------------------------------------------------
    # Live trading safety
    # ------------------------------------------------------------------

    def assert_live_trading_enabled(self):
        """
        Ensure Kraken live trading has been explicitly enabled.

        This method never enables live trading itself.
        """

        if not self.live_trading_enabled:
            raise KrakenConfigurationError(
                "Kraken live trading is disabled."
            )

    # ------------------------------------------------------------------
    # Order submission
    # ------------------------------------------------------------------

    def submit_order(
        self,
        *,
        pair,
        side,
        order_type,
        volume,
        price=None,
        validate_only=False,
        client_order_id=None,
    ):
        """
        Submit a Kraken Spot order.

        This method is protected by the live-trading guard.

        Args:
            pair:
                Kraken trading-pair identifier.

            side:
                "buy" or "sell".

            order_type:
                "market" or "limit".

            volume:
                Base-asset quantity.

            price:
                Required for limit orders.

            validate_only:
                When True, ask Kraken to validate the order without
                executing it.

        Returns:
            dict:
                Kraken AddOrder result.

        Raises:
            KrakenConfigurationError:
                If live trading is disabled or credentials are missing.

            ValueError:
                If order parameters are invalid.

            KrakenAPIError:
                If Kraken rejects the request.
        """

        self.assert_live_trading_enabled()

        pair = str(pair or "").strip()
        side = str(side or "").strip().lower()
        order_type = str(order_type or "").strip().lower()
        volume = str(volume or "").strip()

        if not pair:
            raise ValueError(
                "A Kraken trading pair is required."
            )

        if side not in {"buy", "sell"}:
            raise ValueError(
                "Kraken order side must be buy or sell."
            )

        if order_type not in {"market", "limit"}:
            raise ValueError(
                "Kraken order type must be market or limit."
            )

        if not volume:
            raise ValueError(
                "Kraken order volume is required."
            )

        data = {
            "pair": pair,
            "type": side,
            "ordertype": order_type,
            "volume": volume,
        }

        if order_type == "limit":
            if price is None or not str(price).strip():
                raise ValueError(
                    "A price is required for a Kraken limit order."
                )

            data["price"] = str(price)

        if validate_only:
            data["validate"] = "true"

        if client_order_id is not None:
            client_order_id = str(
                client_order_id
            ).strip()

            if not client_order_id:
                raise ValueError(
                    "Kraken client order ID cannot be empty."
                )

            if len(client_order_id) > 36:
                raise ValueError(
                    "Kraken client order ID is too long."
                )

            data["cl_ord_id"] = client_order_id

        return self._private_request(
            "AddOrder",
            data=data,
        )

    def cancel_order(
        self,
        *,
        exchange_order_id=None,
        client_order_id=None,
    ):
        """Cancel one Kraken Spot order by txid or client order ID."""
        self.assert_live_trading_enabled()

        exchange_order_id = str(exchange_order_id or "").strip()
        client_order_id = str(client_order_id or "").strip()

        if bool(exchange_order_id) == bool(client_order_id):
            raise ValueError(
                "Provide exactly one Kraken order ID or client order ID."
            )

        if exchange_order_id:
            data = {"txid": exchange_order_id}
        else:
            if len(client_order_id) > 36:
                raise ValueError("Kraken client order ID is too long.")
            data = {"cl_ord_id": client_order_id}

        return self._private_request("CancelOrder", data=data)

