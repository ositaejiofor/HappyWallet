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
    """Raised when a Kraken API request fails."""


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
            raise KrakenAPIError(
                f"Kraken request failed: {exc}"
            ) from exc

        if not response.ok:
            raise KrakenAPIError(
                "Kraken returned HTTP "
                f"{response.status_code}."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise KrakenAPIError(
                "Kraken returned invalid JSON."
            ) from exc

        errors = body.get("error") or []

        if errors:
            raise KrakenAPIError(
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
            raise KrakenAPIError(
                f"Kraken request failed: {exc}"
            ) from exc

        if not response.ok:
            raise KrakenAPIError(
                "Kraken returned HTTP "
                f"{response.status_code}."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise KrakenAPIError(
                "Kraken returned invalid JSON."
            ) from exc

        errors = body.get("error") or []

        if errors:
            raise KrakenAPIError(
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
        *args,
        **kwargs,
    ):
        """
        Reject live order submission until the complete safety boundary
        has been implemented.

        Intended execution path:

            Order
                ↓
            LiveExecutionService
                ↓
            validation
                ↓
            confirmation
                ↓
            risk checks
                ↓
            KrakenAdapter
                ↓
            Kraken

        This method intentionally does not submit anything to Kraken.
        """

        self.assert_live_trading_enabled()

        raise KrakenError(
            "Kraken order submission is not implemented yet. "
            "Use LiveExecutionService after the live execution "
            "safety boundary has been completed."
        )