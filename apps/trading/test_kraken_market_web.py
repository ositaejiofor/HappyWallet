"""
Tests for the authenticated Kraken public live-price endpoint.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .services.kraken import KrakenAPIError


class KrakenLivePricesViewTests(TestCase):
    """Test the cached Kraken public-price JSON endpoint."""

    def setUp(self):
        cache.clear()

        self.user = get_user_model().objects.create_user(
            username="kraken-price-user",
            email="kraken-prices@example.com",
            password="TestPassword123!",
        )

        self.client.force_login(self.user)

        self.url = reverse(
            "trading:kraken_live_prices"
        )

    def tearDown(self):
        cache.clear()

    def test_endpoint_returns_public_prices(self):
        payload = {
            "provider": "Kraken",
            "currency": "USD",
            "retrieved_at": (
                "2026-09-21T10:00:00+00:00"
            ),
            "prices": [
                {
                    "symbol": "BTC/USD",
                    "price": "50000.0",
                }
            ],
        }

        with patch(
            "apps.trading.views."
            "KrakenPublicMarketService"
        ) as service_class:
            service = service_class.return_value
            service.get_prices.return_value = payload

            response = self.client.get(self.url)

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertEqual(
            response.json(),
            payload,
        )
        self.assertEqual(
            response["Cache-Control"],
            "private, no-store",
        )

        service.get_prices.assert_called_once_with()

    def test_endpoint_caches_provider_result(self):
        payload = {
            "provider": "Kraken",
            "currency": "USD",
            "retrieved_at": (
                "2026-09-21T10:00:00+00:00"
            ),
            "prices": [],
        }

        with patch(
            "apps.trading.views."
            "KrakenPublicMarketService"
        ) as service_class:
            service = service_class.return_value
            service.get_prices.return_value = payload

            first_response = self.client.get(
                self.url
            )
            second_response = self.client.get(
                self.url
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
            first_response.json(),
            payload,
        )
        self.assertEqual(
            second_response.json(),
            payload,
        )

        service.get_prices.assert_called_once_with()

    def test_endpoint_returns_502_for_kraken_failure(self):
        with patch(
            "apps.trading.views."
            "KrakenPublicMarketService"
        ) as service_class:
            service = service_class.return_value
            service.get_prices.side_effect = (
                KrakenAPIError(
                    "Unavailable"
                )
            )

            response = self.client.get(
                self.url
            )

        self.assertEqual(
            response.status_code,
            502,
        )
        self.assertEqual(
            response.json(),
            {
                "detail": (
                    "Kraken live prices are "
                    "temporarily unavailable."
                ),
            },
        )

        service.get_prices.assert_called_once_with()
