"""Mocked tests for Kraken live-order cancellation."""

import base64
from decimal import Decimal
from unittest.mock import Mock, patch

import requests
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from apps.market.models import MarketAsset

from .models import Order, TradingAccount, TradingPair
from .services.kraken import (
    KrakenAdapter,
    KrakenRejectedError,
    KrakenTransportError,
)
from .services.live_cancel import LiveCancellationError, LiveCancellationService


User = get_user_model()


class KrakenCancelAdapterTests(SimpleTestCase):
    def setUp(self):
        self.session = Mock()
        self.adapter = KrakenAdapter(
            api_key="test-key",
            api_secret=base64.b64encode(b"test-secret").decode(),
            live_trading_enabled=True,
            session=self.session,
        )

    def test_cancel_by_exchange_order_id(self):
        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": [], "result": {"count": 1}
        }
        result = self.adapter.cancel_order(exchange_order_id="KRAKEN-1")
        self.assertEqual(result["count"], 1)
        call = self.session.post.call_args
        self.assertTrue(call.args[0].endswith("/private/CancelOrder"))
        self.assertEqual(call.kwargs["data"]["txid"], "KRAKEN-1")
        self.assertNotIn("cl_ord_id", call.kwargs["data"])

    def test_cancel_requires_exactly_one_identifier(self):
        with self.assertRaises(ValueError):
            self.adapter.cancel_order()
        with self.assertRaises(ValueError):
            self.adapter.cancel_order(
                exchange_order_id="KRAKEN-1", client_order_id="CLIENT-1"
            )
        self.session.post.assert_not_called()

    def test_network_failure_is_transport_error(self):
        self.session.post.side_effect = requests.RequestException("timeout")
        with self.assertRaises(KrakenTransportError):
            self.adapter.cancel_order(exchange_order_id="KRAKEN-1")

    def test_explicit_api_error_is_rejection(self):
        self.session.post.return_value.ok = True
        self.session.post.return_value.json.return_value = {
            "error": ["EOrder:Unknown order"], "result": {}
        }
        with self.assertRaises(KrakenRejectedError):
            self.adapter.cancel_order(exchange_order_id="KRAKEN-1")


class LiveCancellationServiceTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(
            username="cancel-trader",
            email="cancel@example.com",
            password="test-password",
        )
        self.account = TradingAccount.objects.create(
            user=user, mode=TradingAccount.Mode.LIVE, is_active=True
        )
        base = MarketAsset.objects.create(
            symbol="BTC", name="Bitcoin", coingecko_id="bitcoin-cancel"
        )
        quote = MarketAsset.objects.create(
            symbol="USD", name="US Dollar", coingecko_id="usd-cancel"
        )
        pair = TradingPair.objects.create(
            base_asset=base,
            quote_asset=quote,
            symbol="BTC/USD-CANCEL",
            min_order_quantity=Decimal("0.0001"),
        )
        self.order = Order.objects.create(
            account=self.account,
            pair=pair,
            client_order_id="cancel-live-order",
            exchange_order_id="KRAKEN-OPEN-1",
            side=Order.Side.BUY,
            order_type=Order.OrderType.LIMIT,
            quantity=Decimal("0.01"),
            limit_price=Decimal("50000"),
            status=Order.Status.OPEN,
        )
        self.adapter = Mock(spec=KrakenAdapter)
        self.adapter.assert_live_trading_enabled.return_value = None
        self.adapter.cancel_order.return_value = {"count": 1}
        self.service = LiveCancellationService(adapter=self.adapter)

    @override_settings(KRAKEN_LIVE_TRADING_ENABLED=True)
    def test_confirmed_cancel_becomes_cancelled(self):
        result = self.service.cancel(account=self.account, order=self.order)
        self.assertEqual(result.status, Order.Status.CANCELLED)
        self.adapter.cancel_order.assert_called_once_with(
            exchange_order_id="KRAKEN-OPEN-1"
        )

    @override_settings(KRAKEN_LIVE_TRADING_ENABLED=True)
    def test_transport_failure_becomes_cancel_unknown(self):
        self.adapter.cancel_order.side_effect = KrakenTransportError("timeout")
        with self.assertRaises(LiveCancellationError):
            self.service.cancel(account=self.account, order=self.order)
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.CANCEL_UNKNOWN)

    @override_settings(KRAKEN_LIVE_TRADING_ENABLED=True)
    def test_zero_count_becomes_cancel_unknown(self):
        self.adapter.cancel_order.return_value = {"count": 0}
        with self.assertRaises(LiveCancellationError):
            self.service.cancel(account=self.account, order=self.order)
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.CANCEL_UNKNOWN)

    @override_settings(KRAKEN_LIVE_TRADING_ENABLED=False)
    def test_disabled_gate_never_calls_kraken(self):
        with self.assertRaises(LiveCancellationError):
            self.service.cancel(account=self.account, order=self.order)
        self.adapter.cancel_order.assert_not_called()

    @override_settings(KRAKEN_LIVE_TRADING_ENABLED=True)
    def test_order_without_exchange_id_is_rejected(self):
        self.order.exchange_order_id = ""
        self.order.save(update_fields=["exchange_order_id"])
        with self.assertRaises(ValidationError):
            self.service.cancel(account=self.account, order=self.order)
        self.adapter.cancel_order.assert_not_called()


class LiveCancellationWebTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="cancel-web",
            email="cancel-web@example.com",
            password="test-password",
        )
        self.account = TradingAccount.objects.create(
            user=self.user, mode=TradingAccount.Mode.LIVE
        )
        base = MarketAsset.objects.create(
            symbol="ETH", name="Ethereum", coingecko_id="ethereum-cancel-web"
        )
        quote = MarketAsset.objects.create(
            symbol="USD", name="US Dollar", coingecko_id="usd-cancel-web"
        )
        pair = TradingPair.objects.create(
            base_asset=base, quote_asset=quote, symbol="ETH/USD-CANCEL"
        )
        self.order = Order.objects.create(
            account=self.account,
            pair=pair,
            client_order_id="cancel-web-order",
            exchange_order_id="KRAKEN-WEB-1",
            side=Order.Side.SELL,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("1"),
            status=Order.Status.OPEN,
        )
        self.client.force_login(self.user)

    @patch("apps.trading.views.LiveCancellationService")
    def test_wrong_phrase_never_calls_service(self, service):
        response = self.client.post(
            reverse("trading:cancel_live_order", args=[self.order.id]),
            {"acknowledge_live_cancel": "yes", "cancellation_phrase": "wrong"},
        )
        self.assertEqual(response.status_code, 302)
        service.assert_not_called()

    @patch("apps.trading.views.LiveCancellationService")
    def test_complete_confirmation_calls_service(self, service):
        service.return_value.cancel.return_value = self.order
        response = self.client.post(
            reverse("trading:cancel_live_order", args=[self.order.id]),
            {
                "acknowledge_live_cancel": "yes",
                "cancellation_phrase": "CANCEL LIVE ORDER",
            },
        )
        self.assertEqual(response.status_code, 302)
        service.return_value.cancel.assert_called_once_with(
            account=self.account, order=self.order
        )
