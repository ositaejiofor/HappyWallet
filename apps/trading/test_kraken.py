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
                order_type="market",
                volume="0.01",
            )

        self.session.post.assert_not_called()

    def test_submit_market_order_when_live_trading_enabled(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [],
            "result": {
                "descr": {
                    "order": "buy 0.01000000 BTC/USD @ market"
                },
                "txid": [
                    "TEST-KRAKEN-TXID"
                ],
            },
        }

        result = adapter.submit_order(
            pair="BTC/USD",
            side="buy",
            order_type="market",
            volume="0.01",
        )

        self.assertEqual(
            result["txid"],
            ["TEST-KRAKEN-TXID"],
        )

        self.session.post.assert_called_once()

        call = self.session.post.call_args

        self.assertTrue(
            call.args[0].endswith(
                "/private/AddOrder"
            )
        )

        payload = call.kwargs["data"]

        self.assertEqual(
            payload["pair"],
            "BTC/USD",
        )

        self.assertEqual(
            payload["type"],
            "buy",
        )

        self.assertEqual(
            payload["ordertype"],
            "market",
        )

        self.assertEqual(
            payload["volume"],
            "0.01",
        )

        self.assertNotIn(
            "price",
            payload,
        )

        self.assertIn(
            "nonce",
            payload,
        )

    def test_submit_limit_order_requires_price(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            ValueError,
            "A price is required for a Kraken limit order.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                order_type="limit",
                volume="0.01",
            )

        self.session.post.assert_not_called()

    def test_submit_limit_order_includes_price(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [],
            "result": {
                "descr": {
                    "order": (
                        "sell 0.01000000 BTC/USD "
                        "@ limit 100000"
                    )
                },
                "txid": [
                    "TEST-LIMIT-TXID"
                ],
            },
        }

        result = adapter.submit_order(
            pair="BTC/USD",
            side="sell",
            order_type="limit",
            volume="0.01",
            price="100000",
        )

        self.assertEqual(
            result["txid"],
            ["TEST-LIMIT-TXID"],
        )

        payload = (
            self.session.post
            .call_args
            .kwargs["data"]
        )

        self.assertEqual(
            payload["type"],
            "sell",
        )

        self.assertEqual(
            payload["ordertype"],
            "limit",
        )

        self.assertEqual(
            payload["price"],
            "100000",
        )

    def test_validate_only_adds_kraken_validate_flag(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [],
            "result": {
                "descr": {
                    "order": "buy 0.01000000 BTC/USD @ market"
                }
            },
        }

        adapter.submit_order(
            pair="BTC/USD",
            side="buy",
            order_type="market",
            volume="0.01",
            validate_only=True,
        )

        payload = (
            self.session.post
            .call_args
            .kwargs["data"]
        )

        self.assertEqual(
            payload["validate"],
            "true",
        )

    def test_submit_order_rejects_invalid_side(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            ValueError,
            "Kraken order side must be buy or sell.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="invalid",
                order_type="market",
                volume="0.01",
            )

        self.session.post.assert_not_called()

    def test_submit_order_rejects_invalid_order_type(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            ValueError,
            "Kraken order type must be market or limit.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                order_type="invalid",
                volume="0.01",
            )

        self.session.post.assert_not_called()

    def test_submit_order_requires_volume(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            ValueError,
            "Kraken order volume is required.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                order_type="market",
                volume="",
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


class KrakenClientOrderIDTests(SimpleTestCase):

    def setUp(self):
        self.api_key = "test-api-key"

        self.api_secret = base64.b64encode(
            b"test-secret"
        ).decode()

        self.session = Mock()

    def test_submit_order_sends_client_order_id(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [],
            "result": {
                "descr": {
                    "order": "buy 0.01 BTC/USD @ market",
                },
                "txid": [
                    "TEST-TXID",
                ],
            },
        }

        client_order_id = (
            "12345678-1234-5678-1234-567812345678"
        )

        adapter.submit_order(
            pair="BTC/USD",
            side="buy",
            order_type="market",
            volume="0.01",
            client_order_id=client_order_id,
        )

        self.session.post.assert_called_once()

        payload = self.session.post.call_args.kwargs[
            "data"
        ]

        self.assertEqual(
            payload["cl_ord_id"],
            client_order_id,
        )

    def test_submit_order_rejects_empty_client_order_id(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            ValueError,
            "Kraken client order ID cannot be empty.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                order_type="market",
                volume="0.01",
                client_order_id="   ",
            )

        self.session.post.assert_not_called()

    def test_submit_order_rejects_overlong_client_order_id(self):
        adapter = KrakenAdapter(
            api_key=self.api_key,
            api_secret=self.api_secret,
            live_trading_enabled=True,
            session=self.session,
        )

        with self.assertRaisesMessage(
            ValueError,
            "Kraken client order ID is too long.",
        ):
            adapter.submit_order(
                pair="BTC/USD",
                side="buy",
                order_type="market",
                volume="0.01",
                client_order_id="x" * 37,
            )

        self.session.post.assert_not_called()
