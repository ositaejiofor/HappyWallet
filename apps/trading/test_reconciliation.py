from decimal import Decimal
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.market.models import MarketAsset

from .models import (
    Order,
    TradingAccount,
    TradingPair,
)
from .services.kraken import (
    KrakenAPIError,
    KrakenAdapter,
)
from .services.reconciliation import (
    KrakenOrderReconciliationService,
    KrakenReconciliationError,
)


User = get_user_model()


class KrakenOrderReconciliationServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="reconcile-trader",
            email="reconcile@example.com",
            password="test-password",
        )

        self.base_asset = MarketAsset.objects.create(
            symbol="BTC",
            name="Bitcoin",
            coingecko_id="bitcoin-reconcile",
            is_active=True,
        )

        self.quote_asset = MarketAsset.objects.create(
            symbol="USD",
            name="US Dollar",
            coingecko_id="usd-reconcile",
            is_active=True,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.base_asset,
            quote_asset=self.quote_asset,
            symbol="BTC/USD-RECONCILE",
            is_active=True,
            price_precision=2,
            quantity_precision=8,
            min_order_quantity=Decimal("0.0001"),
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
            name="Kraken Reconciliation Account",
            mode=TradingAccount.Mode.LIVE,
            is_active=True,
        )

        self.client_id = (
            "12345678-1234-5678-1234-567812345678"
        )

        self.order = Order.objects.create(
            account=self.account,
            pair=self.pair,
            client_order_id="reconciliation-test-order",
            exchange_client_order_id=self.client_id,
            side=Order.Side.BUY,
            order_type=Order.OrderType.MARKET,
            quantity=Decimal("0.01"),
            status=Order.Status.UNKNOWN,
        )

        self.adapter = Mock(
            spec=KrakenAdapter
        )

        self.service = (
            KrakenOrderReconciliationService(
                adapter=self.adapter
            )
        )

    def test_matching_open_order_becomes_open(self):
        self.adapter.get_open_orders.return_value = {
            "open": {
                "KRAKEN-OPEN-1": {
                    "cl_ord_id": self.client_id,
                    "status": "open",
                }
            }
        }

        result = self.service.reconcile(
            account=self.account,
            order=self.order,
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
            self.order.exchange_order_id,
            "KRAKEN-OPEN-1",
        )

        self.assertEqual(
            self.order.submission_error,
            "",
        )

        self.adapter.get_closed_orders.assert_not_called()
        self.adapter.submit_order.assert_not_called()

    def test_matching_closed_order_becomes_filled(self):
        self.adapter.get_open_orders.return_value = {
            "open": {}
        }

        self.adapter.get_closed_orders.return_value = {
            "closed": {
                "KRAKEN-CLOSED-1": {
                    "cl_ord_id": self.client_id,
                    "status": "closed",
                }
            }
        }

        self.service.reconcile(
            account=self.account,
            order=self.order,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.FILLED,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "KRAKEN-CLOSED-1",
        )

        self.adapter.submit_order.assert_not_called()

    def test_matching_cancelled_order_becomes_cancelled(self):
        self.adapter.get_open_orders.return_value = {
            "open": {}
        }

        self.adapter.get_closed_orders.return_value = {
            "closed": {
                "KRAKEN-CANCELLED-1": {
                    "cl_ord_id": self.client_id,
                    "status": "canceled",
                }
            }
        }

        self.service.reconcile(
            account=self.account,
            order=self.order,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.CANCELLED,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "KRAKEN-CANCELLED-1",
        )

        self.adapter.submit_order.assert_not_called()

    def test_not_found_remains_unknown(self):
        self.adapter.get_open_orders.return_value = {
            "open": {}
        }

        self.adapter.get_closed_orders.return_value = {
            "closed": {}
        }

        self.service.reconcile(
            account=self.account,
            order=self.order,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.assertIn(
            "Automatic resubmission remains blocked",
            self.order.submission_error,
        )

        self.adapter.submit_order.assert_not_called()

    def test_unrecognized_closed_status_remains_unknown(self):
        self.adapter.get_open_orders.return_value = {
            "open": {}
        }

        self.adapter.get_closed_orders.return_value = {
            "closed": {
                "KRAKEN-WEIRD-1": {
                    "cl_ord_id": self.client_id,
                    "status": "mystery-status",
                }
            }
        }

        self.service.reconcile(
            account=self.account,
            order=self.order,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "KRAKEN-WEIRD-1",
        )

        self.adapter.submit_order.assert_not_called()

    def test_submitting_order_can_be_reconciled(self):
        self.order.status = Order.Status.SUBMITTING
        self.order.save(
            update_fields=["status"]
        )

        self.adapter.get_open_orders.return_value = {
            "open": {
                "KRAKEN-OPEN-2": {
                    "cl_ord_id": self.client_id,
                    "status": "open",
                }
            }
        }

        self.service.reconcile(
            account=self.account,
            order=self.order,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.OPEN,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "KRAKEN-OPEN-2",
        )

    def test_pending_order_cannot_be_reconciled(self):
        self.order.status = Order.Status.PENDING
        self.order.save(
            update_fields=["status"]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "This order does not require reconciliation.",
        ):
            self.service.reconcile(
                account=self.account,
                order=self.order,
            )

        self.adapter.get_open_orders.assert_not_called()
        self.adapter.get_closed_orders.assert_not_called()
        self.adapter.submit_order.assert_not_called()

    def test_missing_exchange_client_id_is_rejected(self):
        self.order.exchange_client_order_id = ""
        self.order.save(
            update_fields=[
                "exchange_client_order_id"
            ]
        )

        with self.assertRaisesMessage(
            ValidationError,
            "Order has no exchange client order ID.",
        ):
            self.service.reconcile(
                account=self.account,
                order=self.order,
            )

        self.adapter.get_open_orders.assert_not_called()
        self.adapter.submit_order.assert_not_called()

    def test_kraken_api_failure_preserves_unknown(self):
        self.adapter.get_open_orders.side_effect = (
            KrakenAPIError(
                "temporary query failure"
            )
        )

        with self.assertRaisesMessage(
            KrakenReconciliationError,
            "Kraken reconciliation request failed.",
        ):
            self.service.reconcile(
                account=self.account,
                order=self.order,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.adapter.submit_order.assert_not_called()

    def test_multiple_matches_are_rejected(self):
        self.adapter.get_open_orders.return_value = {
            "open": {
                "KRAKEN-1": {
                    "cl_ord_id": self.client_id,
                },
                "KRAKEN-2": {
                    "cl_ord_id": self.client_id,
                },
            }
        }

        with self.assertRaisesMessage(
            KrakenReconciliationError,
            "multiple orders",
        ):
            self.service.reconcile(
                account=self.account,
                order=self.order,
            )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.adapter.submit_order.assert_not_called()

    def test_other_client_order_id_is_ignored(self):
        self.adapter.get_open_orders.return_value = {
            "open": {
                "SOMEONE-ELSE": {
                    "cl_ord_id": (
                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    ),
                    "status": "open",
                }
            }
        }

        self.adapter.get_closed_orders.return_value = {
            "closed": {}
        }

        self.service.reconcile(
            account=self.account,
            order=self.order,
        )

        self.order.refresh_from_db()

        self.assertEqual(
            self.order.status,
            Order.Status.UNKNOWN,
        )

        self.assertEqual(
            self.order.exchange_order_id,
            "",
        )

        self.adapter.submit_order.assert_not_called()
