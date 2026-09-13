"""
Tests for HappyWallet live trading execution.

These tests NEVER submit real orders.

All exchange-facing components are mocked.
"""

import uuid

from decimal import Decimal
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.market.models import MarketAsset

from .models import (
    Order,
    TradingAccount,
    TradingPair,
)
from .services.kraken import (
    KrakenAPIError,
    KrakenAdapter,
    KrakenConfigurationError,
    KrakenRejectedError,
    KrakenTransportError,
)
from .services.kraken_pairs import (
    KrakenPairError,
    KrakenPairInfo,
)
from .services.live import (
    LiveExecutionError,
    LiveExecutionService,
    LiveTradingDisabledError,
)


User = get_user_model()


class LiveExecutionServiceTests(TestCase):
    """
    Test the HappyWallet live execution safety boundary.

    KrakenAdapter and KrakenPairService are mocked so these tests
    cannot place real exchange orders.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="live-trader",
            email="live@example.com",
            password="test-password",
        )

        self.other_user = User.objects.create_user(
            username="other-trader",
            email="other@example.com",
            password="test-password",
        )

        self.paper_user = User.objects.create_user(
            username="paper-trader",
            email="paper@example.com",
            password="test-password",
        )

        self.base_asset = MarketAsset.objects.create(
            symbol="BTC",
            name="Bitcoin",
            coingecko_id="bitcoin",
            is_active=True,
        )

        self.quote_asset = MarketAsset.objects.create(
            symbol="USD",
            name="US Dollar",
            coingecko_id="usd-test",
            is_active=True,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.base_asset,
            quote_asset=self.quote_asset,
            symbol="BTC/USD",
            is_active=True,
            price_precision=2,
            quantity_precision=8,
            min_order_quantity=Decimal("0.0001"),
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
            name="Live Kraken Account",
            mode=TradingAccount.Mode.LIVE,
            is_active=True,
        )

        self.paper_account = TradingAccount.objects.create(
            user=self.paper_user,
            name="Paper Account",
            mode=TradingAccount.Mode.PAPER,
            is_active=True,
        )

        self.other_account = TradingAccount.objects.create(
            user=self.other_user,
            name="Other Live Account",
            mode=TradingAccount.Mode.LIVE,
            is_active=True,
        )

        self.order = Order.objects.create(
            account=self.account,
            pair=self.pair,
            client_order_id="live-test-order-1",
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.010000009"),
            status=Order.Status.PENDING,
        )

        self.adapter = Mock(
            spec=KrakenAdapter
        )
        self.pair_service = Mock()

        self.pair_info = KrakenPairInfo(
            happywallet_symbol="BTC/USD",
            kraken_symbol="XBTUSD",
            base_asset="BTC",
            quote_asset="USD",
            price_precision=2,
            quantity_precision=8,
            minimum_order_quantity=Decimal("0.0001"),
            active=True,
        )

        self.pair_service.resolve.return_value = (
            self.pair_info
        )

        self.adapter.assert_live_trading_enabled.return_value = None

        self.adapter.submit_order.return_value = {
            "descr": {
                "order": (
                    "buy 0.01000000 XBTUSD @ market"
                ),
            },
            "txid": [
                "TEST-KRAKEN-TXID",
            ],
        }

        self.service = LiveExecutionService(
            adapter=self.adapter,
            pair_service=self.pair_service,
            confirmation_required=True,
        )

        self.kraken_client_order_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                (
                    "happywallet:kraken:"
                    f"{self.order.client_order_id}"
                ),
            )
        )

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_successful_market_order_becomes_open(self):
        result = self.service.execute(
            account=self.account,
            order=self.order,
            confirmed=True,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            result.pk,
            self.order.pk,
        )

        self.assertEqual(
            self.order.status,
            Order.Status.OPEN,
        )

        self.assertEqual(
            self.order.exchange_client_order_id,
            self.kraken_client_order_id,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "TEST-KRAKEN-TXID",
        )

        self.assertIsNotNone(
            self.order.submitted_at
        )

        self.assertEqual(
            self.order.submission_error,
            "",
        )

        self.pair_service.resolve.assert_called_once_with(
            self.pair
        )

        self.adapter.submit_order.assert_called_once_with(
            pair="XBTUSD",
            side="buy",
            order_type="market",
            volume="0.01000000",
            client_order_id=self.kraken_client_order_id,
        )

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=False
    )
    def test_application_live_switch_blocks_submission(self):
        with self.assertRaisesMessage(
            LiveTradingDisabledError,
            "Kraken live trading is disabled.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.pair_service.resolve.assert_not_called()
        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_adapter_live_switch_blocks_submission(self):
        self.adapter.assert_live_trading_enabled.side_effect = (
            KrakenConfigurationError(
                "Kraken live trading is disabled."
            )
        )

        with self.assertRaisesMessage(
            LiveTradingDisabledError,
            "Kraken live trading is disabled.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.pair_service.resolve.assert_not_called()
        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_confirmation_is_required(self):
        with self.assertRaisesMessage(
            ValidationError,
            "Live order confirmation is required.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=False,
            )

        self.adapter.assert_live_trading_enabled.assert_not_called()
        self.pair_service.resolve.assert_not_called()
        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_paper_account_cannot_execute_live_order(self):
        paper_order = Order.objects.create(
            account=self.paper_account,
            pair=self.pair,
            client_order_id="paper-live-test",
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.01"),
            status=Order.Status.PENDING,
        )

        with self.assertRaisesMessage(
            ValidationError,
            "Live execution requires a live trading account.",
        ):
            self.service.execute(
                account=self.paper_account,
                order=paper_order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_order_must_belong_to_account(self):
        with self.assertRaisesMessage(
            ValidationError,
            "This order does not belong to the trading account.",
        ):
            self.service.execute(
                account=self.other_account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_inactive_account_is_rejected(self):
        self.account.is_active = False
        self.account.save(
            update_fields=["is_active"]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "Trading account is inactive.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_filled_order_cannot_execute_again(self):
        self.order.status = Order.Status.FILLED
        self.order.save(
            update_fields=["status"]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be submitted.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_quantity_is_rounded_down_to_kraken_precision(self):
        self.service.execute(
            account=self.account,
            order=self.order,
            confirmed=True,
        )

        self.adapter.submit_order.assert_called_once_with(
            pair="XBTUSD",
            side="buy",
            order_type="market",
            volume="0.01000000",
            client_order_id=self.kraken_client_order_id,
        )

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_quantity_below_kraken_minimum_is_rejected(self):
        self.order.quantity = Decimal(
            "0.000099999"
        )
        self.order.save(
            update_fields=["quantity"]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "Minimum order quantity is",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_limit_order_includes_rounded_price(self):
        self.order.order_type = (
            Order.OrderType.LIMIT
        )
        self.order.limit_price = Decimal(
            "100000.129"
        )

        self.order.save(
            update_fields=[
                "order_type",
                "limit_price",
            ]
        )

        self.service.execute(
            account=self.account,
            order=self.order,
            confirmed=True,
        )

        self.adapter.submit_order.assert_called_once_with(
            pair="XBTUSD",
            side="buy",
            order_type="limit",
            volume="0.01000000",
            price="100000.12",
            client_order_id=self.kraken_client_order_id,
        )

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_pair_resolution_failure_is_wrapped(self):
        self.pair_service.resolve.side_effect = (
            KrakenPairError(
                "pair metadata unavailable"
            )
        )

        with self.assertRaisesMessage(
            LiveExecutionError,
            "Kraken pair resolution failed",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_unclassified_kraken_api_failure_becomes_unknown(self):
        self.adapter.submit_order.side_effect = (
            KrakenAPIError(
                "temporary exchange failure"
            )
        )

        with self.assertRaisesMessage(
            LiveExecutionError,
            "Kraken order submission outcome is unknown.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_client_order_id,
            self.kraken_client_order_id,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.assertIsNotNone(
            self.order.submitted_at
        )

        self.assertIn(
            "temporary exchange failure",
            self.order.submission_error,
        )

        self.adapter.submit_order.assert_called_once()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_transport_failure_becomes_unknown(self):
        self.adapter.submit_order.side_effect = (
            KrakenTransportError(
                "connection timed out"
            )
        )

        with self.assertRaisesMessage(
            LiveExecutionError,
            "Reconciliation is required before retrying.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_client_order_id,
            self.kraken_client_order_id,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.assertIsNotNone(
            self.order.submitted_at
        )

        self.assertIn(
            "connection timed out",
            self.order.submission_error,
        )

        self.adapter.submit_order.assert_called_once()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_explicit_kraken_rejection_becomes_rejected(self):
        self.adapter.submit_order.side_effect = (
            KrakenRejectedError(
                "EOrder:Insufficient funds"
            )
        )

        with self.assertRaisesMessage(
            LiveExecutionError,
            "Kraken order rejected:",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.REJECTED,
        )

        self.assertEqual(
            self.order.exchange_client_order_id,
            self.kraken_client_order_id,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.assertIsNotNone(
            self.order.submitted_at
        )

        self.assertIn(
            "Insufficient funds",
            self.order.submission_error,
        )

        self.adapter.submit_order.assert_called_once()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_invalid_kraken_response_becomes_unknown(self):
        self.adapter.submit_order.return_value = None

        with self.assertRaisesMessage(
            LiveExecutionError,
            "Kraken returned an invalid order response.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_client_order_id,
            self.kraken_client_order_id,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.assertIsNotNone(
            self.order.submitted_at
        )

        self.assertEqual(
            self.order.submission_error,
            "Kraken returned an invalid order response.",
        )

        self.adapter.submit_order.assert_called_once()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_missing_kraken_txid_becomes_unknown(self):
        self.adapter.submit_order.return_value = {
            "descr": {
                "order": "test",
            },
            "txid": [],
        }

        with self.assertRaisesMessage(
            LiveExecutionError,
            "Kraken did not return a valid order transaction ID.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_client_order_id,
            self.kraken_client_order_id,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.assertIsNotNone(
            self.order.submitted_at
        )

        self.assertEqual(
            self.order.submission_error,
            (
                "Kraken did not return a valid "
                "order transaction ID."
            ),
        )

        self.adapter.submit_order.assert_called_once()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_open_order_cannot_be_submitted_again(self):
        self.order.status = Order.Status.OPEN
        self.order.save(
            update_fields=["status"]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be submitted.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_submitting_order_cannot_be_submitted_again(self):
        self.order.status = Order.Status.SUBMITTING
        self.order.exchange_client_order_id = (
            self.kraken_client_order_id
        )

        self.order.save(
            update_fields=[
                "status",
                "exchange_client_order_id",
            ]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be submitted.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_unknown_order_cannot_be_submitted_again(self):
        self.order.status = Order.Status.UNKNOWN
        self.order.exchange_client_order_id = (
            self.kraken_client_order_id
        )

        self.order.save(
            update_fields=[
                "status",
                "exchange_client_order_id",
            ]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be submitted.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

    @override_settings(
        KRAKEN_LIVE_TRADING_ENABLED=True
    )
    def test_rejected_order_cannot_be_submitted_again(self):
        self.order.status = Order.Status.REJECTED
        self.order.save(
            update_fields=["status"]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "This order cannot be submitted.",
        ):
            self.service.execute(
                account=self.account,
                order=self.order,
                confirmed=True,
            )

        self.adapter.submit_order.assert_not_called()

