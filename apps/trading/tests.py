from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase

from apps.market.models import MarketAsset, MarketPrice

from .models import (
    Order,
    Trade,
    TradingAccount,
    TradingBalance,
    TradingPair,
)
from .services.order_service import OrderService
from .services.paper import PaperTradingEngine


User = get_user_model()


class TradingAccountModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="trader",
            email="trader@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
            name="Main Trading Account",
            mode=TradingAccount.Mode.PAPER,
        )

    def test_trading_account_creation(self):
        self.assertEqual(self.account.user, self.user)
        self.assertEqual(
            self.account.mode,
            TradingAccount.Mode.PAPER,
        )
        self.assertTrue(self.account.is_active)

    def test_is_paper_property(self):
        self.assertTrue(self.account.is_paper)

        self.account.mode = TradingAccount.Mode.LIVE

        self.assertFalse(self.account.is_paper)

    def test_string_representation(self):
        self.assertEqual(
            str(self.account),
            "Main Trading Account - trader@example.com",
        )


class TradingBalanceModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="balance-user",
            email="balance-user@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
        )

        self.asset = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            decimals=18,
        )

        self.balance = TradingBalance.objects.create(
            account=self.account,
            asset=self.asset,
            available=Decimal("10.500000000000000000"),
            locked=Decimal("2.000000000000000000"),
        )

    def test_total_balance(self):
        self.assertEqual(
            self.balance.total,
            Decimal("12.500000000000000000"),
        )

    def test_string_representation(self):
        self.assertIn(
            "ETH",
            str(self.balance),
        )

    def test_unique_account_asset_balance(self):
        with self.assertRaises(IntegrityError):
            TradingBalance.objects.create(
                account=self.account,
                asset=self.asset,
                available=Decimal("1"),
            )


class TradingPairModelTests(TestCase):
    def setUp(self):
        self.eth = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            decimals=18,
        )

        self.usdt = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
            decimals=6,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.eth,
            quote_asset=self.usdt,
            symbol="ETH/USDT",
            min_order_quantity=Decimal("0.00000001"),
            price_precision=8,
            quantity_precision=8,
        )

    def test_trading_pair_creation(self):
        self.assertEqual(
            self.pair.base_asset,
            self.eth,
        )
        self.assertEqual(
            self.pair.quote_asset,
            self.usdt,
        )
        self.assertEqual(
            self.pair.symbol,
            "ETH/USDT",
        )
        self.assertTrue(self.pair.is_active)

    def test_string_representation(self):
        self.assertEqual(
            str(self.pair),
            "ETH/USDT",
        )


class OrderModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="order-user",
            email="order-user@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
        )

        self.eth = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            decimals=18,
        )

        self.usdt = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
            decimals=6,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.eth,
            quote_asset=self.usdt,
            symbol="ETH/USDT",
        )

        self.order = Order.objects.create(
            account=self.account,
            pair=self.pair,
            client_order_id="test-order-001",
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.100000000000000000"),
            status=Order.Status.FILLED,
            filled_quantity=Decimal("0.100000000000000000"),
            average_fill_price=Decimal("2452.370000000000000000"),
        )

    def test_remaining_quantity(self):
        self.assertEqual(
            self.order.remaining_quantity,
            Decimal("0"),
        )

    def test_is_complete(self):
        self.assertTrue(self.order.is_complete)

    def test_string_representation(self):
        self.assertEqual(
            str(self.order),
            "BUY 0.100000000000000000 ETH/USDT",
        )


class TradeModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="trade-user",
            email="trade-user@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
        )

        self.eth = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
        )

        self.usdt = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.eth,
            quote_asset=self.usdt,
            symbol="ETH/USDT",
        )

        self.order = Order.objects.create(
            account=self.account,
            pair=self.pair,
            client_order_id="trade-order-001",
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.1"),
            filled_quantity=Decimal("0.1"),
            average_fill_price=Decimal("2452.37"),
            status=Order.Status.FILLED,
        )

        self.trade = Trade.objects.create(
            order=self.order,
            execution_id="paper-test-execution-001",
            quantity=Decimal("0.1"),
            price=Decimal("2452.37"),
            fee=Decimal("1.00"),
            fee_asset=self.usdt,
        )

    def test_trade_creation(self):
        self.assertEqual(
            self.trade.order,
            self.order,
        )
        self.assertEqual(
            self.trade.quantity,
            Decimal("0.1"),
        )
        self.assertEqual(
            self.trade.price,
            Decimal("2452.37"),
        )

    def test_notional_value(self):
        self.assertEqual(
            self.trade.notional_value,
            Decimal("245.237"),
        )

    def test_string_representation(self):
        self.assertIn(
            "paper-test-execution-001",
            str(self.trade),
        )


class TradingRelationshipTests(TestCase):
    def test_order_and_trade_relationship(self):
        user = User.objects.create_user(
            username="relationship-user",
            email="relationship-user@example.com",
            password="test-password",
        )

        account = TradingAccount.objects.create(
            user=user,
        )

        eth = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
        )

        usdt = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
        )

        pair = TradingPair.objects.create(
            base_asset=eth,
            quote_asset=usdt,
            symbol="ETH/USDT",
        )

        order = Order.objects.create(
            account=account,
            pair=pair,
            client_order_id="relationship-order-001",
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.1"),
        )

        trade = Trade.objects.create(
            order=order,
            execution_id="relationship-execution-001",
            quantity=Decimal("0.1"),
            price=Decimal("2500"),
        )

        self.assertEqual(
            order.trades.count(),
            1,
        )
        self.assertEqual(
            order.trades.first(),
            trade,
        )
        self.assertEqual(
            order.account,
            account,
        )
        self.assertEqual(
            order.pair,
            pair,
        )


class MarketPriceIntegrationTests(TestCase):
    def test_trading_pair_can_have_market_price(self):
        eth = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
        )

        usdt = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
        )

        pair = TradingPair.objects.create(
            base_asset=eth,
            quote_asset=usdt,
            symbol="ETH/USDT",
        )

        price = MarketPrice.objects.create(
            asset=eth,
            price_usd=Decimal("2452.37"),
        )

        self.assertEqual(
            pair.base_asset,
            price.asset,
        )
        self.assertEqual(
            pair.base_asset.prices.first(),
            price,
        )


class PaperTradingEngineTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="paper-trader",
            email="paper-trader@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
            mode=TradingAccount.Mode.PAPER,
        )

        self.eth = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            decimals=18,
        )

        self.usdt = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
            decimals=6,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.eth,
            quote_asset=self.usdt,
            symbol="ETH/USDT",
        )

        self.price = Decimal("2500")

        MarketPrice.objects.create(
            asset=self.eth,
            price_usd=self.price,
        )

    def create_order(
        self,
        *,
        side=Order.Side.BUY,
        quantity=Decimal("1"),
        order_type=Order.OrderType.MARKET,
        limit_price=None,
        client_order_id="paper-order-001",
        status=Order.Status.PENDING,
    ):
        return Order.objects.create(
            account=self.account,
            pair=self.pair,
            client_order_id=client_order_id,
            side=side,
            order_type=order_type,
            quantity=quantity,
            limit_price=limit_price,
            status=status,
        )

    def create_balance(self, asset, amount):
        return TradingBalance.objects.create(
            account=self.account,
            asset=asset,
            available=amount,
        )

    def test_market_buy_executes(self):
        quote_balance = self.create_balance(
            self.usdt,
            Decimal("5000"),
        )
        base_balance = self.create_balance(
            self.eth,
            Decimal("0"),
        )

        order = self.create_order(
            quantity=Decimal("1"),
        )

        trade = PaperTradingEngine.execute(order)

        quote_balance.refresh_from_db()
        base_balance.refresh_from_db()
        order.refresh_from_db()

        self.assertEqual(
            quote_balance.available,
            Decimal("2500"),
        )
        self.assertEqual(
            base_balance.available,
            Decimal("1"),
        )
        self.assertEqual(
            trade.quantity,
            Decimal("1"),
        )
        self.assertEqual(
            trade.price,
            self.price,
        )
        self.assertEqual(
            order.status,
            Order.Status.FILLED,
        )
        self.assertEqual(
            order.filled_quantity,
            Decimal("1"),
        )
        self.assertEqual(
            order.average_fill_price,
            self.price,
        )
        self.assertEqual(
            order.trades.count(),
            1,
        )

    def test_market_sell_executes(self):
        base_balance = self.create_balance(
            self.eth,
            Decimal("2"),
        )
        quote_balance = self.create_balance(
            self.usdt,
            Decimal("0"),
        )

        order = self.create_order(
            side=Order.Side.SELL,
            quantity=Decimal("1"),
            client_order_id="paper-sell-001",
        )

        trade = PaperTradingEngine.execute(order)

        base_balance.refresh_from_db()
        quote_balance.refresh_from_db()
        order.refresh_from_db()

        self.assertEqual(
            base_balance.available,
            Decimal("1"),
        )
        self.assertEqual(
            quote_balance.available,
            Decimal("2500"),
        )
        self.assertEqual(
            trade.quantity,
            Decimal("1"),
        )
        self.assertEqual(
            trade.price,
            self.price,
        )
        self.assertEqual(
            order.status,
            Order.Status.FILLED,
        )

    def test_buy_rejects_insufficient_quote_balance(self):
        quote_balance = self.create_balance(
            self.usdt,
            Decimal("1000"),
        )
        base_balance = self.create_balance(
            self.eth,
            Decimal("0"),
        )

        order = self.create_order(
            quantity=Decimal("1"),
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        quote_balance.refresh_from_db()
        base_balance.refresh_from_db()
        order.refresh_from_db()

        self.assertEqual(
            quote_balance.available,
            Decimal("1000"),
        )
        self.assertEqual(
            base_balance.available,
            Decimal("0"),
        )
        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )
        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_sell_rejects_insufficient_base_balance(self):
        base_balance = self.create_balance(
            self.eth,
            Decimal("0.5"),
        )
        quote_balance = self.create_balance(
            self.usdt,
            Decimal("0"),
        )

        order = self.create_order(
            side=Order.Side.SELL,
            quantity=Decimal("1"),
            client_order_id="paper-sell-insufficient-001",
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        base_balance.refresh_from_db()
        quote_balance.refresh_from_db()
        order.refresh_from_db()

        self.assertEqual(
            base_balance.available,
            Decimal("0.5"),
        )
        self.assertEqual(
            quote_balance.available,
            Decimal("0"),
        )
        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )
        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_live_account_is_rejected(self):
        self.account.mode = TradingAccount.Mode.LIVE
        self.account.save(update_fields=["mode"])

        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order()

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )
        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_filled_order_is_rejected(self):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            status=Order.Status.FILLED,
            client_order_id="paper-filled-001",
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_cancelled_order_is_rejected(self):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            status=Order.Status.CANCELLED,
            client_order_id="paper-cancelled-001",
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_limit_buy_executes_when_market_price_is_at_limit(self):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            order_type=Order.OrderType.LIMIT,
            limit_price=Decimal("2500"),
            client_order_id="paper-limit-buy-001",
        )

        trade = PaperTradingEngine.execute(order)

        self.assertEqual(
            trade.price,
            Decimal("2500"),
        )

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.FILLED,
        )

    def test_limit_buy_rejects_price_above_limit(self):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            order_type=Order.OrderType.LIMIT,
            limit_price=Decimal("2400"),
            client_order_id="paper-limit-buy-reject-001",
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )
        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_limit_sell_executes_when_market_price_is_at_limit(self):
        self.create_balance(
            self.eth,
            Decimal("2"),
        )

        order = self.create_order(
            side=Order.Side.SELL,
            quantity=Decimal("1"),
            order_type=Order.OrderType.LIMIT,
            limit_price=Decimal("2500"),
            client_order_id="paper-limit-sell-001",
        )

        trade = PaperTradingEngine.execute(order)

        self.assertEqual(
            trade.price,
            Decimal("2500"),
        )

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.FILLED,
        )

    def test_limit_sell_rejects_price_below_limit(self):
        self.create_balance(
            self.eth,
            Decimal("2"),
        )

        order = self.create_order(
            side=Order.Side.SELL,
            quantity=Decimal("1"),
            order_type=Order.OrderType.LIMIT,
            limit_price=Decimal("2600"),
            client_order_id="paper-limit-sell-reject-001",
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )
        self.assertEqual(
            order.trades.count(),
            0,
        )

    @patch(
        "apps.trading.services.paper.get_latest_price",
        return_value=Decimal("2600"),
    )
    def test_engine_uses_latest_market_price(self, mock_get_price):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            quantity=Decimal("1"),
            client_order_id="paper-price-001",
        )

        trade = PaperTradingEngine.execute(order)

        mock_get_price.assert_called_once_with(self.pair)

        self.assertEqual(
            trade.price,
            Decimal("2600"),
        )

    @patch(
        "apps.trading.services.paper.get_latest_price",
        side_effect=ValidationError("Price unavailable."),
    )
    def test_price_failure_leaves_order_unchanged(self, mock_get_price):
        quote_balance = self.create_balance(
            self.usdt,
            Decimal("5000"),
        )
        base_balance = self.create_balance(
            self.eth,
            Decimal("0"),
        )

        order = self.create_order(
            quantity=Decimal("1"),
            client_order_id="paper-price-failure-001",
        )

        with self.assertRaises(ValidationError):
            PaperTradingEngine.execute(order)

        mock_get_price.assert_called_once_with(self.pair)

        quote_balance.refresh_from_db()
        base_balance.refresh_from_db()
        order.refresh_from_db()

        self.assertEqual(
            quote_balance.available,
            Decimal("5000"),
        )
        self.assertEqual(
            base_balance.available,
            Decimal("0"),
        )
        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )
        self.assertEqual(
            order.trades.count(),
            0,
        )

    def test_execution_id_is_paper_prefixed(self):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            client_order_id="paper-execution-id-001",
        )

        trade = PaperTradingEngine.execute(order)

        self.assertTrue(
            trade.execution_id.startswith("paper-"),
        )

    def test_engine_does_not_create_real_wallet_records(self):
        self.create_balance(
            self.usdt,
            Decimal("5000"),
        )

        order = self.create_order(
            client_order_id="paper-isolation-001",
        )

        PaperTradingEngine.execute(order)

        self.assertEqual(
            Trade.objects.filter(order=order).count(),
            1,
        )
        self.assertEqual(
            TradingBalance.objects.filter(
                account=self.account,
            ).count(),
            2,
        )


class OrderServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="order-service-user",
            email="order-service@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
            name="Order Service Account",
            mode=TradingAccount.Mode.PAPER,
            is_active=True,
        )

        self.base_asset = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            decimals=18,
        )

        self.quote_asset = MarketAsset.objects.create(
            symbol="USDT",
            name="Tether",
            coingecko_id="tether",
            decimals=6,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.base_asset,
            quote_asset=self.quote_asset,
            symbol="ETH/USDT",
            is_active=True,
            min_order_quantity=Decimal("0.001"),
            max_order_quantity=Decimal("100"),
            quantity_precision=3,
            price_precision=2,
        )

    def create_order(self, **overrides):
        values = {
            "account": self.account,
            "pair": self.pair,
            "side": Order.Side.BUY,
            "order_type": Order.OrderType.MARKET,
            "quantity": Decimal("1.000"),
            "limit_price": None,
        }
        values.update(overrides)

        return OrderService.create_order(**values)

    def test_create_market_order(self):
        order = self.create_order()

        self.assertEqual(order.account, self.account)
        self.assertEqual(order.pair, self.pair)
        self.assertEqual(order.side, Order.Side.BUY)
        self.assertEqual(
            order.order_type,
            Order.OrderType.MARKET,
        )
        self.assertEqual(
            order.quantity,
            Decimal("1.000"),
        )
        self.assertIsNone(order.limit_price)
        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )

    def test_create_limit_order(self):
        order = self.create_order(
            side=Order.Side.SELL,
            order_type=Order.OrderType.LIMIT,
            quantity=Decimal("2.000"),
            limit_price=Decimal("2500.00"),
        )

        self.assertEqual(order.side, Order.Side.SELL)
        self.assertEqual(
            order.order_type,
            Order.OrderType.LIMIT,
        )
        self.assertEqual(
            order.quantity,
            Decimal("2.000"),
        )
        self.assertEqual(
            order.limit_price,
            Decimal("2500.00"),
        )
        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )

    def test_create_order_generates_client_order_id(self):
        order = self.create_order()

        self.assertTrue(order.client_order_id)
        self.assertEqual(
            len(order.client_order_id),
            32,
        )

    def test_create_order_generates_unique_client_order_ids(self):
        first = self.create_order(
            quantity=Decimal("1.000"),
        )
        second = self.create_order(
            quantity=Decimal("2.000"),
        )

        self.assertNotEqual(
            first.client_order_id,
            second.client_order_id,
        )

    def test_inactive_account_is_rejected(self):
        self.account.is_active = False
        self.account.save(update_fields=["is_active"])

        with self.assertRaisesMessage(
            ValidationError,
            "Trading account is inactive.",
        ):
            self.create_order()

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_live_account_is_rejected(self):
        self.account.mode = TradingAccount.Mode.LIVE
        self.account.save(update_fields=["mode"])

        with self.assertRaisesMessage(
            ValidationError,
            "Live trading is not enabled.",
        ):
            self.create_order()

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_inactive_pair_is_rejected(self):
        self.pair.is_active = False
        self.pair.save(update_fields=["is_active"])

        with self.assertRaises(ValidationError):
            self.create_order()

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_zero_quantity_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.create_order(
                quantity=Decimal("0"),
            )

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_quantity_below_minimum_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.create_order(
                quantity=Decimal("0.0001"),
            )

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_quantity_above_maximum_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.create_order(
                quantity=Decimal("101"),
            )

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_limit_order_requires_limit_price(self):
        with self.assertRaises(ValidationError):
            self.create_order(
                order_type=Order.OrderType.LIMIT,
                limit_price=None,
            )

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_limit_order_rejects_non_positive_limit_price(self):
        with self.assertRaises(ValidationError):
            self.create_order(
                order_type=Order.OrderType.LIMIT,
                limit_price=Decimal("0"),
            )

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_market_order_rejects_limit_price(self):
        with self.assertRaises(ValidationError):
            self.create_order(
                order_type=Order.OrderType.MARKET,
                limit_price=Decimal("2500"),
            )

        self.assertEqual(
            Order.objects.count(),
            0,
        )

    def test_cancel_pending_order(self):
        order = self.create_order()

        cancelled = OrderService.cancel_order(
            account=self.account,
            order=order,
        )

        cancelled.refresh_from_db()

        self.assertEqual(
            cancelled.status,
            Order.Status.CANCELLED,
        )

    def test_cancel_open_order(self):
        order = self.create_order()

        order.status = Order.Status.OPEN
        order.save(update_fields=["status"])

        cancelled = OrderService.cancel_order(
            account=self.account,
            order=order,
        )

        self.assertEqual(
            cancelled.status,
            Order.Status.CANCELLED,
        )

    def test_cancel_partially_filled_order(self):
        order = self.create_order()

        order.status = Order.Status.PARTIALLY_FILLED
        order.save(update_fields=["status"])

        cancelled = OrderService.cancel_order(
            account=self.account,
            order=order,
        )

        self.assertEqual(
            cancelled.status,
            Order.Status.CANCELLED,
        )

    def test_cannot_cancel_completed_order(self):
        order = self.create_order()

        order.status = Order.Status.FILLED
        order.save(update_fields=["status"])

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be cancelled.",
        ):
            OrderService.cancel_order(
                account=self.account,
                order=order,
            )

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.FILLED,
        )

    def test_cannot_cancel_cancelled_order(self):
        order = self.create_order()

        order.status = Order.Status.CANCELLED
        order.save(update_fields=["status"])

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be cancelled.",
        ):
            OrderService.cancel_order(
                account=self.account,
                order=order,
            )

    def test_cannot_cancel_order_belonging_to_another_account(self):
        other_user = User.objects.create_user(
            username="other-order-user",
            email="other-order@example.com",
            password="test-password",
        )

        other_account = TradingAccount.objects.create(
            user=other_user,
            name="Other Account",
            mode=TradingAccount.Mode.PAPER,
            is_active=True,
        )

        order = self.create_order()

        with self.assertRaisesMessage(
            ValidationError,
            "This order does not belong to the trading account.",
        ):
            OrderService.cancel_order(
                account=other_account,
                order=order,
            )

        order.refresh_from_db()

        self.assertEqual(
            order.status,
            Order.Status.PENDING,
        )