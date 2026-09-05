import requests


class CoinGeckoError(Exception):
    """Raised when the CoinGecko API cannot be used safely."""


class CoinGeckoProvider:
    """
    Thin HTTP client for CoinGecko.

    This class is intentionally independent of Django models.
    """

    BASE_URL = "https://api.coingecko.com/api/v3"

    def __init__(
        self,
        api_key=None,
        timeout=10,
    ):
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self):
        headers = {
            "Accept": "application/json",
        }

        if self.api_key:
            headers["x-cg-demo-api-key"] = self.api_key

        return headers

    def _get(self, endpoint, params=None):
        url = f"{self.BASE_URL}{endpoint}"

        try:
            response = requests.get(
                url,
                params=params or {},
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise CoinGeckoError(
                f"CoinGecko request failed: {exc}"
            ) from exc

        if response.status_code == 429:
            raise CoinGeckoError(
                "CoinGecko rate limit exceeded."
            )

        if not response.ok:
            raise CoinGeckoError(
                f"CoinGecko returned HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise CoinGeckoError(
                "CoinGecko returned invalid JSON."
            ) from exc

    def get_markets(
        self,
        vs_currency="usd",
        page=1,
        per_page=100,
        order="market_cap_desc",
    ):
        return self._get(
            "/coins/markets",
            params={
                "vs_currency": vs_currency,
                "order": order,
                "per_page": per_page,
                "page": page,
                "sparkline": "false",
            },
        )

    def get_coin(self, coin_id):
        return self._get(
            f"/coins/{coin_id}",
            params={
                "localization": "false",
                "tickers": "false",
                "market_data": "true",
                "community_data": "false",
                "developer_data": "false",
            },
        )

    def get_market_chart(
        self,
        coin_id,
        vs_currency="usd",
        days=1,
    ):
        return self._get(
            f"/coins/{coin_id}/market_chart",
            params={
                "vs_currency": vs_currency,
                "days": days,
            },
        )
        
        