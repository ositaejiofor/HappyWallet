"""Web-boundary tests for controlled live trading.

All exchange services are mocked. These tests cannot place real orders.
"""

from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.market.models import MarketAsset

from .models import Order, TradingAccount, TradingPair


User = get_user_model()


class LiveTradingWebTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="web-live-trader",
            email="web-live@example.com",
            password="test-password",
        )
        self.account = TradingAccount.objects.create(
            user=self.user,
            mode=TradingAccount.Mode.LIVE,
            is_active=True,
        )
        base = MarketAsset.objects.create(
            symbol="BTC",
            name="Bitcoin",
            coingecko_id="bitcoin-web-live",
        )
        quote = MarketAsset.objects.create(
            symbol="USD",
            name="US Dollar",
            coingecko_id="usd-web-live",
        )
        self.pair = TradingPair.objects.create(
            base_asset=base,
            quote_asset=quote,
            symbol="BTC/USD",
            min_order_quantity=Decimal("0.0001"),
        )
        self.order = Order.objects.create(
            account=self.account,
            pair=self.pair,
            client_order_id="web-live-order",
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.01"),
        )
        self.client.force_login(self.user)

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True,
        KRAKEN_API_KEY="test-key",
        KRAKEN_API_SECRET="dGVzdC1zZWNyZXQ=",
    )
    def test_order_detail_shows_explicit_live_confirmation(self):
        response = self.client.get(
            reverse("trading:order_detail", args=[self.order.id])
        )
        self.assertContains(response, "Submit Live Order to Kraken")
        self.assertContains(response, "PLACE LIVE ORDER")

    @patch("apps.trading.views.LiveExecutionService")
    def test_missing_confirmation_never_calls_live_service(self, service):
        response = self.client.post(
            reverse("trading:execute_live_order", args=[self.order.id]),
            {"acknowledge_live_risk": "yes", "confirmation_phrase": "wrong"},
        )
        self.assertEqual(response.status_code, 302)
        service.assert_not_called()

    @patch("apps.trading.views.LiveExecutionService")
    def test_complete_confirmation_calls_guarded_service(self, service):
        service.return_value.execute.return_value = self.order
        response = self.client.post(
            reverse("trading:execute_live_order", args=[self.order.id]),
            {
                "acknowledge_live_risk": "yes",
                "confirmation_phrase": "PLACE LIVE ORDER",
            },
        )
        self.assertEqual(response.status_code, 302)
        service.return_value.execute.assert_called_once_with(
            account=self.account,
            order=self.order,
            confirmed=True,
        )

    @patch("apps.trading.views.PaperTradingEngine.execute")
    def test_live_order_cannot_use_paper_execution_endpoint(self, execute):
        response = self.client.post(
            reverse("trading:execute_paper_order", args=[self.order.id])
        )
        self.assertEqual(response.status_code, 302)
        execute.assert_not_called()

    def test_other_user_cannot_submit_live_order(self):
        other = User.objects.create_user(
            username="other-web-trader",
            email="other-web@example.com",
            password="test-password",
        )
        TradingAccount.objects.create(user=other)
        self.client.force_login(other)
        response = self.client.post(
            reverse("trading:execute_live_order", args=[self.order.id]),
            {
                "acknowledge_live_risk": "yes",
                "confirmation_phrase": "PLACE LIVE ORDER",
            },
        )
        self.assertEqual(response.status_code, 404)


class LiveOrderIntentTests(TestCase):
    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True,
        KRAKEN_API_KEY="test-key",
        KRAKEN_API_SECRET="dGVzdC1zZWNyZXQ=",
    )
    def test_live_account_can_create_pending_intent_when_fully_gated(self):
        user = User.objects.create_user(
            username="live-intent",
            email="live-intent@example.com",
            password="test-password",
        )
        account = TradingAccount.objects.create(
            user=user,
            mode=TradingAccount.Mode.LIVE,
        )
        base = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum-live-intent",
        )
        quote = MarketAsset.objects.create(
            symbol="USD",
            name="US Dollar",
            coingecko_id="usd-live-intent",
        )
        pair = TradingPair.objects.create(
            base_asset=base,
            quote_asset=quote,
            symbol="ETH/USD",
        )
        from .services import OrderService

        order = OrderService.create_order(
            account=account,
            pair=pair,
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("1"),
        )
        self.assertEqual(order.status, Order.Status.PENDING)

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True,
        KRAKEN_API_KEY="",
        KRAKEN_API_SECRET="",
    )
    def test_live_intent_requires_configured_credentials(self):
        from django.core.exceptions import ValidationError
        from .services import OrderService

        user = User.objects.create_user(
            username="missing-live-credentials",
            email="missing-live@example.com",
            password="test-password",
        )
        account = TradingAccount.objects.create(
            user=user,
            mode=TradingAccount.Mode.LIVE,
        )
        base = MarketAsset.objects.create(
            symbol="SOL",
            name="Solana",
            coingecko_id="solana-live-intent",
        )
        quote = MarketAsset.objects.create(
            symbol="USD",
            name="US Dollar",
            coingecko_id="usd-live-intent-missing",
        )
        pair = TradingPair.objects.create(
            base_asset=base,
            quote_asset=quote,
            symbol="SOL/USD",
        )
        with self.assertRaisesMessage(
            ValidationError,
            "Kraken live-trading credentials are not configured.",
        ):
            OrderService.create_order(
                account=account,
                pair=pair,
                side=Order.Side.BUY,
                order_type=Order.OrderType.MARKET,
                quantity=Decimal("1"),
            )
