"""
Tests for the HappyWallet Kraken trading adapter.
"""

import base64
from unittest.mock import Mock

from django.test import SimpleTestCase

from .services.kraken import (
    KrakenAPIError,
    KrakenAdapter,
    KrakenConfigurationError,
)


class KrakenAdapterTests(SimpleTestCase):
    """
    Unit tests for KrakenAdapter.

    These tests do not make real requests to Kraken.
    All HTTP communication is mocked.
    """

    def setUp(self):
        self.session = Mock()

        self.adapter = KrakenAdapter(
            api_key="test-api-key",
            api_secret=base64.b64encode(
                b"test-secret"
            ).decode(),
            timeout=10,
            live_trading_enabled=False,
            session=self.session,
        )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def test_is_configured_when_credentials_exist(self):
        self.assertTrue(
            self.adapter.is_configured
        )

    def test_is_not_configured_without_api_key(self):
        adapter = KrakenAdapter(
            api_key="",
            api_secret="test-secret",
            session=self.session,
        )

        self.assertFalse(
            adapter.is_configured
        )

    def test_is_not_configured_without_api_secret(self):
        adapter = KrakenAdapter(
            api_key="test-api-key",
            api_secret="",
            session=self.session,
        )

        self.assertFalse(
            adapter.is_configured
        )

    def test_validate_configuration_requires_api_key(self):
        adapter = KrakenAdapter(
            api_key="",
            api_secret="test-secret",
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "KRAKEN_API_KEY is not configured.",
        ):
            adapter.validate_configuration()

    def test_validate_configuration_requires_api_secret(self):
        adapter = KrakenAdapter(
            api_key="test-api-key",
            api_secret="",
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "KRAKEN_API_SECRET is not configured.",
        ):
            adapter.validate_configuration()

    # ------------------------------------------------------------------
    # Nonce
    # ------------------------------------------------------------------

    def test_nonce_is_strictly_increasing(self):
        first = self.adapter._nonce()
        second = self.adapter._nonce()
        third = self.adapter._nonce()

        self.assertLess(
            int(first),
            int(second),
        )

        self.assertLess(
            int(second),
            int(third),
        )

    def test_nonce_remains_increasing_with_same_timestamp(self):
        self.adapter._last_nonce = 2_000_000_000_000

        first = self.adapter._nonce()
        second = self.adapter._nonce()

        self.assertEqual(
            int(first),
            2_000_000_000_001,
        )

        self.assertEqual(
            int(second),
            2_000_000_000_002,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def test_get_server_time(self):
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.return_value = {
            "error": [],
            "result": {
                "unixtime": 1750000000,
                "rfc1123": "Sun, 15 Jun 2025 00:00:00 GMT",
            },
        }

        result = self.adapter.get_server_time()

        self.assertEqual(
            result["unixtime"],
            1750000000,
        )

        self.session.get.assert_called_once()

        call = self.session.get.call_args

        self.assertEqual(
            call.kwargs["timeout"],
            10,
        )

    def test_get_asset_pairs(self):
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.return_value = {
            "error": [],
            "result": {
                "XXBTZUSD": {
                    "altname": "XBTUSD",
                },
            },
        }

        result = self.adapter.get_asset_pairs()

        self.assertIn(
            "XXBTZUSD",
            result,
        )

        call = self.session.get.call_args

        self.assertEqual(
            call.kwargs["params"],
            {},
        )

    def test_get_asset_pairs_with_pair(self):
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.return_value = {
            "error": [],
            "result": {
                "XXBTZUSD": {
                    "altname": "XBTUSD",
                },
            },
        }

        result = self.adapter.get_asset_pairs(
            pair="XBTUSD",
        )

        self.assertIn(
            "XXBTZUSD",
            result,
        )

        call = self.session.get.call_args

        self.assertEqual(
            call.kwargs["params"],
            {
                "pair": "XBTUSD",
            },
        )

    def test_get_ticker(self):
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.return_value = {
            "error": [],
            "result": {
                "XXBTZUSD": {
                    "a": [
                        "100000.0",
                        "1",
                        "1.000",
                    ],
                    "b": [
                        "99999.0",
                        "1",
                        "1.000",
                    ],
                    "c": [
                        "100000.0",
                        "0.001",
                    ],
                },
            },
        }

        result = self.adapter.get_ticker(
            "XBTUSD",
        )

        self.assertIn(
            "XXBTZUSD",
            result,
        )

        call = self.session.get.call_args

        self.assertEqual(
            call.kwargs["params"],
            {
                "pair": "XBTUSD",
            },
        )

    def test_get_ticker_requires_pair(self):
        with self.assertRaisesMessage(
            ValueError,
            "A Kraken trading pair is required.",
        ):
            self.adapter.get_ticker("")

    # ------------------------------------------------------------------
    # Public API errors
    # ------------------------------------------------------------------

    def test_public_request_handles_http_error(self):
        self.session.get.return_value.ok = False
        self.session.get.return_value.status_code = 503

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken returned HTTP 503.",
        ):
            self.adapter.get_server_time()

    def test_public_request_handles_invalid_json(self):
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.side_effect = ValueError

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken returned invalid JSON.",
        ):
            self.adapter.get_server_time()

    def test_public_request_handles_api_error(self):
        self.session.get.return_value.ok = True
        self.session.get.return_value.json.return_value = {
            "error": [
                "EGeneral:Temporary lockout",
            ],
            "result": {},
        }

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken API returned an error: "
            "EGeneral:Temporary lockout",
        ):
            self.adapter.get_server_time()

    def test_public_request_handles_connection_error(self):
        import requests

        self.session.get.side_effect = (
            requests.RequestException(
                "connection failed"
            )
        )

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken request failed: connection failed",
        ):
            self.adapter.get_server_time()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def test_private_request_requires_credentials(self):
        adapter = KrakenAdapter(
            api_key="",
            api_secret="",
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "KRAKEN_API_KEY is not configured.",
        ):
            adapter.get_account_balance()

        self.session.post.assert_not_called()

    def test_private_request_adds_nonce(self):
        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [],
            "result": {
                "ZUSD": "1000.00",
            },
        }

        result = self.adapter.get_account_balance()

        self.assertEqual(
            result["ZUSD"],
            "1000.00",
        )

        call = self.session.post.call_args

        payload = call.kwargs["data"]

        self.assertIn(
            "nonce",
            payload,
        )

        self.assertTrue(
            str(payload["nonce"]).isdigit()
        )

    def test_private_request_sends_authentication_headers(self):
        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [],
            "result": {},
        }

        self.adapter.get_account_balance()

        call = self.session.post.call_args

        headers = call.kwargs["headers"]

        self.assertEqual(
            headers["API-Key"],
            "test-api-key",
        )

        self.assertTrue(
            headers["API-Sign"]
        )

    def test_private_request_handles_http_error(self):
        self.session.post.return_value.ok = False
        self.session.post.return_value.status_code = 401

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken returned HTTP 401.",
        ):
            self.adapter.get_account_balance()

    def test_private_request_handles_invalid_json(self):
        self.session.post.return_value.ok = True
        self.session.post.return_value.json.side_effect = ValueError

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken returned invalid JSON.",
        ):
            self.adapter.get_account_balance()

    # ------------------------------------------------------------------
    # Live trading safety
    # ------------------------------------------------------------------

    def test_live_trading_is_disabled_by_default(self):
        adapter = KrakenAdapter(
            api_key="test-api-key",
            api_secret="test-secret",
            session=self.session,
            live_trading_enabled=False,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "Kraken live trading is disabled.",
        ):
            adapter.assert_live_trading_enabled()

    def test_live_trading_guard_allows_enabled_adapter(self):
        adapter = KrakenAdapter(
            api_key="test-api-key",
            api_secret="test-secret",
            session=self.session,
            live_trading_enabled=True,
        )

        adapter.assert_live_trading_enabled()

    def test_submit_order_remains_blocked(self):
        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "Kraken live trading is disabled.",
        ):
            self.adapter.submit_order(
                pair="XBTUSD",
                side="buy",
                order_type="market",
                volume="0.01",
            )

        self.session.post.assert_not_called()