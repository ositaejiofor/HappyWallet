from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .models import MarketAsset
from .services.providers.coingecko import (
    CoinGeckoError,
)


class LiveMarketChartTests(TestCase):
    def setUp(self):
        cache.clear()

        self.asset = MarketAsset.objects.create(
            symbol="BTC",
            name="Bitcoin",
            coingecko_id="bitcoin",
            is_active=True,
        )

        self.url = reverse(
            "market:asset_chart_data",
            args=["bitcoin"],
        )


    def tearDown(self):
        cache.clear()


    @patch(
        "apps.market.views."
        "MarketPriceService.historical_candles"
    )
    def test_chart_endpoint_returns_normalized_ohlc_data(
        self,
        historical_candles,
    ):
        historical_candles.return_value = [
            [
                1000,
                10.00,
                12.00,
                9.00,
                11.00,
            ],
            [
                2000,
                11.00,
                13.00,
                10.00,
                12.50,
            ],
        ]

        response = self.client.get(
            self.url,
            {
                "days": 7,
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        payload = response.json()

        self.assertEqual(
            payload["coin_id"],
            "bitcoin",
        )

        self.assertEqual(
            payload["symbol"],
            "BTC",
        )

        self.assertEqual(
            payload["currency"],
            "USD",
        )

        self.assertEqual(
            payload["days"],
            7,
        )

        self.assertEqual(
            payload["candles"],
            [
                [
                    1000,
                    10.0,
                    12.0,
                    9.0,
                    11.0,
                ],
                [
                    2000,
                    11.0,
                    13.0,
                    10.0,
                    12.5,
                ],
            ],
        )

        historical_candles.assert_called_once_with(
            coin_id="bitcoin",
            days=7,
            vs_currency="usd",
        )


    def test_chart_endpoint_rejects_unsupported_range(
        self,
    ):
        response = self.client.get(
            self.url,
            {
                "days": 999,
            },
        )

        self.assertEqual(
            response.status_code,
            400,
        )

        self.assertIn(
            "error",
            response.json(),
        )


    def test_chart_endpoint_rejects_non_integer_range(
        self,
    ):
        response = self.client.get(
            self.url,
            {
                "days": "invalid",
            },
        )

        self.assertEqual(
            response.status_code,
            400,
        )

        self.assertIn(
            "error",
            response.json(),
        )


    def test_chart_endpoint_returns_404_for_unknown_asset(
        self,
    ):
        response = self.client.get(
            reverse(
                "market:asset_chart_data",
                args=["unknown"],
            ),
        )

        self.assertEqual(
            response.status_code,
            404,
        )


    @patch(
        "apps.market.views."
        "MarketPriceService.historical_candles"
    )
    def test_provider_failure_returns_safe_message(
        self,
        historical_candles,
    ):
        historical_candles.side_effect = (
            CoinGeckoError(
                "Secret provider failure information."
            )
        )

        response = self.client.get(
            self.url,
            {
                "days": 1,
            },
        )

        self.assertEqual(
            response.status_code,
            502,
        )

        content = response.content.decode(
            "utf-8"
        )

        self.assertNotIn(
            "Secret provider failure information.",
            content,
        )

        self.assertEqual(
            response.json()["error"],
            (
                "Live candlestick data is "
                "temporarily unavailable."
            ),
        )


    @patch(
        "apps.market.views."
        "MarketPriceService.historical_candles"
    )
    def test_chart_response_is_cached(
        self,
        historical_candles,
    ):
        historical_candles.return_value = [
            [
                1000,
                10.00,
                12.00,
                9.00,
                11.00,
            ],
            [
                2000,
                11.00,
                13.00,
                10.00,
                12.00,
            ],
        ]

        first_response = self.client.get(
            self.url,
            {
                "days": 1,
            },
        )

        second_response = self.client.get(
            self.url,
            {
                "days": 1,
            },
        )

        self.assertEqual(
            first_response.status_code,
            200,
        )

        self.assertEqual(
            second_response.status_code,
            200,
        )

        self.assertEqual(
            historical_candles.call_count,
            1,
        )