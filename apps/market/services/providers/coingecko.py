from __future__ import annotations

from typing import Any

import requests


class CoinGeckoError(Exception):
    """
    Raised when CoinGecko cannot be accessed or returns invalid data.
    """


class CoinGeckoProvider:
    """
    Read-only HTTP client for the CoinGecko public API.

    This provider:

    - retrieves public cryptocurrency information;
    - never accesses wallet keys;
    - never signs transactions;
    - never broadcasts transactions;
    - never places trades.
    """

    BASE_URL = "https://api.coingecko.com/api/v3"

    SUPPORTED_OHLC_DAYS = {
        1,
        7,
        14,
        30,
        90,
        180,
        365,
    }

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 10.0,
    ):
        self.api_key = (
            api_key.strip()
            if isinstance(api_key, str)
            else ""
        )

        self.timeout = max(
            float(timeout),
            1.0,
        )


    def _headers(self) -> dict[str, str]:
        """
        Build safe HTTP request headers.
        """

        headers = {
            "Accept": "application/json",
            "User-Agent": "HappyWallet/0.1",
        }

        if self.api_key:
            headers["x-cg-demo-api-key"] = (
                self.api_key
            )

        return headers


    def _get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """
        Perform a read-only GET request.
        """

        if not endpoint.startswith("/"):
            raise CoinGeckoError(
                "CoinGecko endpoint must begin with '/'."
            )

        url = f"{self.BASE_URL}{endpoint}"

        try:
            response = requests.get(
                url,
                params=params or {},
                headers=self._headers(),
                timeout=self.timeout,
            )

        except requests.Timeout as exc:
            raise CoinGeckoError(
                "CoinGecko request timed out."
            ) from exc

        except requests.RequestException as exc:
            raise CoinGeckoError(
                "CoinGecko request failed."
            ) from exc


        if response.status_code == 429:
            raise CoinGeckoError(
                "CoinGecko rate limit exceeded. "
                "Please try again shortly."
            )

        if not response.ok:
            raise CoinGeckoError(
                "CoinGecko returned HTTP "
                f"{response.status_code}."
            )


        try:
            return response.json()

        except ValueError as exc:
            raise CoinGeckoError(
                "CoinGecko returned invalid JSON."
            ) from exc


    def get_markets(
        self,
        vs_currency: str = "usd",
        page: int = 1,
        per_page: int = 100,
        order: str = "market_cap_desc",
    ) -> list[dict[str, Any]]:
        """
        Retrieve the current cryptocurrency market list.
        """

        result = self._get(
            "/coins/markets",
            params={
                "vs_currency": vs_currency,
                "order": order,
                "per_page": per_page,
                "page": page,
                "sparkline": "false",
            },
        )

        if not isinstance(result, list):
            raise CoinGeckoError(
                "CoinGecko returned an invalid "
                "market response."
            )

        return result


    def get_coin(
        self,
        coin_id: str,
    ) -> dict[str, Any]:
        """
        Retrieve public information for one asset.
        """

        coin_id = self._validate_coin_id(
            coin_id
        )

        result = self._get(
            f"/coins/{coin_id}",
            params={
                "localization": "false",
                "tickers": "false",
                "market_data": "true",
                "community_data": "false",
                "developer_data": "false",
            },
        )

        if not isinstance(result, dict):
            raise CoinGeckoError(
                "CoinGecko returned invalid "
                "asset information."
            )

        return result


    def get_market_chart(
        self,
        coin_id: str,
        vs_currency: str = "usd",
        days: int = 1,
    ) -> dict[str, Any]:
        """
        Retrieve historical price-point data.

        This remains available for services that need ordinary
        price, market-cap and volume time series.
        """

        coin_id = self._validate_coin_id(
            coin_id
        )

        result = self._get(
            f"/coins/{coin_id}/market_chart",
            params={
                "vs_currency": vs_currency,
                "days": days,
            },
        )

        if not isinstance(result, dict):
            raise CoinGeckoError(
                "CoinGecko returned invalid "
                "historical market data."
            )

        return result


    def get_ohlc(
        self,
        coin_id: str,
        vs_currency: str = "usd",
        days: int = 1,
    ) -> list[list[float]]:
        """
        Retrieve genuine OHLC candlestick data.

        CoinGecko returns each candle as:

            [
                timestamp,
                open,
                high,
                low,
                close,
            ]

        No candles are manufactured from ordinary price points.
        """

        coin_id = self._validate_coin_id(
            coin_id
        )

        try:
            days = int(days)

        except (TypeError, ValueError) as exc:
            raise CoinGeckoError(
                "OHLC days must be an integer."
            ) from exc


        if days not in self.SUPPORTED_OHLC_DAYS:
            allowed = ", ".join(
                str(value)
                for value in sorted(
                    self.SUPPORTED_OHLC_DAYS
                )
            )

            raise CoinGeckoError(
                "Unsupported OHLC range. "
                f"Allowed days: {allowed}."
            )


        result = self._get(
            f"/coins/{coin_id}/ohlc",
            params={
                "vs_currency": vs_currency,
                "days": days,
            },
        )

        if not isinstance(result, list):
            raise CoinGeckoError(
                "CoinGecko returned invalid OHLC data."
            )


        candles: list[list[float]] = []

        for item in result:
            if (
                not isinstance(item, list)
                or len(item) < 5
            ):
                continue

            try:
                timestamp = int(item[0])
                open_price = float(item[1])
                high_price = float(item[2])
                low_price = float(item[3])
                close_price = float(item[4])

            except (
                TypeError,
                ValueError,
                OverflowError,
            ):
                continue


            if high_price < low_price:
                continue

            if high_price < max(
                open_price,
                close_price,
            ):
                continue

            if low_price > min(
                open_price,
                close_price,
            ):
                continue


            candles.append(
                [
                    timestamp,
                    open_price,
                    high_price,
                    low_price,
                    close_price,
                ]
            )


        if not candles:
            raise CoinGeckoError(
                "CoinGecko returned no valid "
                "OHLC candles."
            )

        return candles


    @staticmethod
    def _validate_coin_id(
        coin_id: str,
    ) -> str:
        """
        Validate a CoinGecko asset identifier before placing it
        inside a URL path.
        """

        if not isinstance(coin_id, str):
            raise CoinGeckoError(
                "CoinGecko asset ID is required."
            )

        coin_id = coin_id.strip().lower()

        if not coin_id:
            raise CoinGeckoError(
                "CoinGecko asset ID is required."
            )

        allowed_characters = set(
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_"
        )

        if any(
            character not in allowed_characters
            for character in coin_id
        ):
            raise CoinGeckoError(
                "CoinGecko asset ID contains "
                "unsupported characters."
            )

        return coin_id
    
    