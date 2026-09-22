from unittest.mock import Mock

from django.test import SimpleTestCase

from .services.kraken import KrakenAPIError
from .services.kraken_market import KrakenPublicMarketService


class KrakenPublicMarketServiceTests(SimpleTestCase):
    def setUp(self):
        self.adapter = Mock()
        self.service = KrakenPublicMarketService(
            adapter=self.adapter,
        )

    def test_get_price_normalizes_kraken_ticker(self):
        self.adapter.get_ticker.return_value = {
            "XXBTZUSD": {
                "a": ["50110.0", "1", "1.000"],
                "b": ["50090.0", "1", "1.000"],
                "c": ["50100.0", "0.010"],
                "v": ["100.0", "250.0"],
                "h": ["50500.0", "51000.0"],
                "l": ["49000.0", "48000.0"],
                "o": "50000.0",
            }
        }

        price = self.service.get_price(
            "BTC/USD",
            "XBTUSD",
        )

        self.adapter.get_ticker.assert_called_once_with(
            "XBTUSD"
        )
        self.assertEqual(price["symbol"], "BTC/USD")
        self.assertEqual(price["price"], "50100.0")
        self.assertEqual(price["bid"], "50090.0")
        self.assertEqual(price["ask"], "50110.0")
        self.assertEqual(price["high_24h"], "51000.0")
        self.assertEqual(price["low_24h"], "48000.0")
        self.assertEqual(price["volume_24h"], "250.0")
        self.assertEqual(
            price["change_percentage_24h"],
            "0.20",
        )

    def test_get_price_rejects_empty_result(self):
        self.adapter.get_ticker.return_value = {}

        with self.assertRaisesRegex(
            KrakenAPIError,
            "empty ticker result",
        ):
            self.service.get_price(
                "BTC/USD",
                "XBTUSD",
            )

    def test_get_price_rejects_incomplete_result(self):
        self.adapter.get_ticker.return_value = {
            "XXBTZUSD": {
                "c": ["50100.0"],
            }
        }

        with self.assertRaisesRegex(
            KrakenAPIError,
            "incomplete ticker data",
        ):
            self.service.get_price(
                "BTC/USD",
                "XBTUSD",
            )

    def test_get_prices_uses_supported_pairs(self):
        self.adapter.get_ticker.return_value = {
            "PAIR": {
                "a": ["101"],
                "b": ["99"],
                "c": ["100"],
                "v": ["5", "10"],
                "h": ["105", "110"],
                "l": ["95", "90"],
                "o": "80",
            }
        }

        result = self.service.get_prices()

        self.assertEqual(result["provider"], "Kraken")
        self.assertEqual(result["currency"], "USD")
        self.assertEqual(
            len(result["prices"]),
            len(self.service.SUPPORTED_PAIRS),
        )
        self.assertEqual(
            self.adapter.get_ticker.call_count,
            len(self.service.SUPPORTED_PAIRS),
        )