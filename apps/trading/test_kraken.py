import base64
from unittest.mock import Mock

import requests
from django.test import SimpleTestCase

from apps.trading.services.kraken import (
    KrakenAPIError,
    KrakenConfigurationError,
    KrakenError,
    KrakenAdapter,
)


class KrakenAdapterTests(SimpleTestCase):

    def setUp(self):
        self.api_key = "test-api-key"

        self.api_secret = base64.b64encode(
            b"test-secret"
        ).decode()

        self.session = Mock()

        self.adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            session=self.session,
        )

    def test_is_configured_when_credentials_exist(self):
        self.assertTrue(
            self.adapter.is_configured
        )

    def test_is_not_configured_without_api_key(self):
        adapter = KrakenAdapter(
            api_key="",
            api_secret=self.api_secret,
            session=self.session,
        )

        self.assertFalse(
            adapter.is_configured
        )

    def test_is_not_configured_without_api_secret(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret="",
            session=self.session,
        )

        self.assertFalse(
            adapter.is_configured
        )

    def test_missing_api_key_raises_configuration_error(self):
        adapter = KrakenAdapter(
            api_key="",
            api_secret=self.api_secret,
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "KRAKEN_API_KEY is not configured.",
        ):
            adapter.validate_configuration()

        self.session.post.assert_not_called()

    def test_missing_api_secret_raises_configuration_error(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret="",
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "KRAKEN_API_SECRET is not configured.",
        ):
            adapter.validate_configuration()

        self.session.post.assert_not_called()

    def test_invalid_base64_secret_raises_configuration_error(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret="not-valid-base64!!!",
            session=self.session,
        )

        with self.assertRaises(
            KrakenConfigurationError
        ):
            adapter._signature(
                "/0/private/Balance",
                {"nonce": "123456789"},
            )

    def test_signature_is_generated(self):
        signature = self.adapter._signature(
            "/0/private/Balance",
            {"nonce": "123456789"},
        )

        self.assertIsInstance(
            signature,
            str,
        )

        self.assertTrue(
            signature
        )

    def test_private_request_sends_authentication_headers(self):
        response = Mock()
        response.ok = True
        response.json.return_value = {
            "error": [],
            "result": {
                "ZUSD": "1000.00",
            },
        }

        self.session.post.return_value = response

        result = self.adapter.get_account_balance()

        self.assertEqual(
            result["ZUSD"],
            "1000.00",
        )

        self.session.post.assert_called_once()

        call = self.session.post.call_args

        url = call.args[0]

        headers = call.kwargs["headers"]
        payload = call.kwargs["data"]

        self.assertEqual(
            url,
            "https://api.kraken.com/0/private/Balance",
        )

        self.assertEqual(
            headers["API-Key"],
            self.api_key,
        )

        self.assertTrue(
            headers["API-Sign"]
        )

        self.assertIn(
            "nonce",
            payload,
        )

    def test_private_request_returns_result(self):
        response = Mock()
        response.ok = True
        response.json.return_value = {
            "error": [],
            "result": {
                "XXBT": "0.50000000",
                "ZUSD": "2500.00",
            },
        }

        self.session.post.return_value = response

        result = self.adapter.get_account_balance()

        self.assertEqual(
            result["XXBT"],
            "0.50000000",
        )

        self.assertEqual(
            result["ZUSD"],
            "2500.00",
        )

    def test_kraken_api_error_is_raised(self):
        response = Mock()
        response.ok = True
        response.json.return_value = {
            "error": [
                "EAPI:Invalid key",
            ],
            "result": {},
        }

        self.session.post.return_value = response

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken API returned an error: EAPI:Invalid key",
        ):
            self.adapter.get_account_balance()

    def test_http_error_is_raised(self):
        response = Mock()
        response.ok = False
        response.status_code = 403

        self.session.post.return_value = response

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken returned HTTP 403.",
        ):
            self.adapter.get_account_balance()

    def test_invalid_json_is_raised(self):
        response = Mock()
        response.ok = True
        response.json.side_effect = ValueError

        self.session.post.return_value = response

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken returned invalid JSON.",
        ):
            self.adapter.get_account_balance()

    def test_network_failure_is_raised(self):
        self.session.post.side_effect = (
            requests.RequestException(
                "connection failed"
            )
        )

        with self.assertRaisesMessage(
            KrakenAPIError,
            "Kraken request failed: connection failed",
        ):
            self.adapter.get_account_balance()

    def test_live_trading_is_disabled_by_default(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=False,
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "Kraken live trading is disabled.",
        ):
            adapter.assert_live_trading_enabled()

    def test_submit_order_is_blocked_when_live_trading_disabled(self):
        with self.assertRaisesMessage(
            KrakenConfigurationError,
            "Kraken live trading is disabled.",
        ):
            self.adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                quantity="0.01",
            )

        self.session.post.assert_not_called()

    def test_submit_order_still_not_implemented_when_enabled(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            KrakenError,
            "Kraken order submission is not implemented yet.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                quantity="0.01",
            )

        self.session.post.assert_not_called()

    def test_credentials_are_not_in_configuration_errors(self):
        adapter = KrakenAdapter(
            api_key="SUPER-SECRET-KEY",
            api_secret=self.api_secret,
            session=self.session,
        )

        adapter.api_key = ""

        with self.assertRaises(
            KrakenConfigurationError
        ) as context:
            adapter.validate_configuration()

        self.assertNotIn(
            "SUPER-SECRET-KEY",
            str(context.exception),
        )
