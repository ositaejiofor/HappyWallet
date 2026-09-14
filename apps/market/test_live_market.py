from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .services.providers.coingecko import CoinGeckoError


class LiveMarketDataTests(TestCase):
    def setUp(self):
        cache.clear()
        self.url = reverse("market:live_data")

    def tearDown(self):
        cache.clear()

    @patch(
        "apps.market.views."
        "MarketPriceService.live_markets"
    )
    def test_live_endpoint_returns_normalized_assets(
        self,
        live_markets,
    ):
        live_markets.return_value = [
            {
                "id": "bitcoin",
                "symbol": "btc",
                "name": "Bitcoin",
                "image": "https://example.com/bitcoin.png",
                "current_price": 76814,
                "market_cap": 1539098816258,
                "total_volume": 15537558986,
                "price_change_percentage_24h": -0.88,
                "market_cap_rank": 1,
                "last_updated": "2026-09-14T09:00:00Z",
            },
            {
                "id": "",
                "symbol": "",
                "name": "",
            },
            "invalid-row",
        ]

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(payload["currency"], "USD")
        self.assertEqual(len(payload["assets"]), 1)
        self.assertEqual(
            payload["assets"][0]["coin_id"],
            "bitcoin",
        )
        self.assertEqual(
            payload["assets"][0]["symbol"],
            "BTC",
        )

        live_markets.assert_called_once_with(
            vs_currency="usd",
            page=1,
            per_page=100,
        )

    @patch(
        "apps.market.views."
        "MarketPriceService.live_markets"
    )
    def test_live_response_is_cached(
        self,
        live_markets,
    ):
        live_markets.return_value = [
            {
                "id": "bitcoin",
                "symbol": "btc",
                "name": "Bitcoin",
            },
        ]

        first = self.client.get(self.url)
        second = self.client.get(self.url)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            first.json(),
            second.json(),
        )
        live_markets.assert_called_once()

    @patch(
        "apps.market.views."
        "MarketPriceService.live_markets"
    )
    def test_provider_failure_returns_safe_error(
        self,
        live_markets,
    ):
        live_markets.side_effect = CoinGeckoError(
            "Private provider information."
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json()["error"],
            (
                "Live market information is "
                "temporarily unavailable."
            ),
        )
        self.assertNotIn(
            "Private provider information.",
            response.content.decode("utf-8"),
        )

    def test_live_endpoint_rejects_post(self):
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 405)
