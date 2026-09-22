"""Tests for the read-only Kraken account service."""

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from .models import TradingAccount
from .services.kraken import KrakenAdapter
from .services.kraken_account import (
    KrakenAccountDataError,
    KrakenAccountService,
)


class KrakenAccountServiceTests(SimpleTestCase):
    def setUp(self):
        self.account = SimpleNamespace(
            is_active=True,
            mode=TradingAccount.Mode.LIVE,
        )

        self.adapter = Mock(
            spec=KrakenAdapter
        )

        self.adapter.get_account_balance.return_value = {
            "XXBT": "0.50000000",
            "ZUSD": "2500.00",
            "XETH": "0",
        }

        self.adapter.get_open_orders.return_value = {
            "open": {
                "OPEN-KRAKEN-12345678": {
                    "status": "open",
                    "opentm": 1758450000,
                    "vol": "0.10000000",
                    "vol_exec": "0.02000000",
                    "cost": "200.00",
                    "fee": "0.50",
                    "price": "10000.00",
                    "descr": {
                        "pair": "XBTUSD",
                        "type": "buy",
                        "ordertype": "limit",
                        "order": (
                            "buy 0.10000000 XBTUSD "
                            "@ limit 10000.00"
                        ),
                    },
                },
            },
        }

        self.adapter.get_closed_orders.return_value = {
            "closed": {
                "CLOSED-KRAKEN-87654321": {
                    "status": "closed",
                    "opentm": 1758440000,
                    "closetm": 1758441000,
                    "vol": "0.05000000",
                    "vol_exec": "0.05000000",
                    "cost": "500.00",
                    "fee": "1.00",
                    "price": "10000.00",
                    "descr": {
                        "pair": "XBTUSD",
                        "type": "sell",
                        "ordertype": "market",
                        "order": (
                            "sell 0.05000000 XBTUSD "
                            "@ market"
                        ),
                    },
                },
            },
            "count": 1,
        }

        self.service = KrakenAccountService(
            adapter=self.adapter
        )

    def test_load_returns_normalized_account_data(self):
        result = self.service.load(
            account=self.account
        )

        self.assertEqual(
            result["balances"],
            [
                {
                    "asset": "BTC",
                    "amount": Decimal("0.50000000"),
                },
                {
                    "asset": "USD",
                    "amount": Decimal("2500.00"),
                },
            ],
        )

        self.assertEqual(
            len(result["open_orders"]),
            1,
        )

        self.assertEqual(
            result["open_orders"][0]["pair"],
            "XBTUSD",
        )

        self.assertEqual(
            result["open_orders"][0]["order_id"],
            "••••12345678",
        )

        self.assertEqual(
            len(result["closed_orders"]),
            1,
        )

        self.assertIsNotNone(
            result["retrieved_at"]
        )

        self.adapter.get_account_balance.assert_called_once_with()

        self.adapter.get_open_orders.assert_called_once_with(
            trades=False
        )

        self.adapter.get_closed_orders.assert_called_once_with(
            trades=False
        )

    def test_zero_balances_are_hidden(self):
        result = self.service.load(
            account=self.account
        )

        assets = {
            item["asset"]
            for item in result["balances"]
        }

        self.assertNotIn(
            "ETH",
            assets,
        )

    def test_paper_account_is_rejected_before_kraken(self):
        self.account.mode = TradingAccount.Mode.PAPER

        with self.assertRaisesMessage(
            ValidationError,
            "Kraken account data requires a live trading account.",
        ):
            self.service.load(
                account=self.account
            )

        self.adapter.get_account_balance.assert_not_called()
        self.adapter.get_open_orders.assert_not_called()
        self.adapter.get_closed_orders.assert_not_called()

    def test_inactive_account_is_rejected_before_kraken(self):
        self.account.is_active = False

        with self.assertRaisesMessage(
            ValidationError,
            "Trading account is inactive.",
        ):
            self.service.load(
                account=self.account
            )

        self.adapter.get_account_balance.assert_not_called()

    def test_invalid_balance_payload_is_rejected(self):
        self.adapter.get_account_balance.return_value = []

        with self.assertRaisesMessage(
            KrakenAccountDataError,
            "Kraken returned invalid balance data.",
        ):
            self.service.load(
                account=self.account
            )

    def test_invalid_order_payload_is_rejected(self):
        self.adapter.get_open_orders.return_value = {
            "open": [],
        }

        with self.assertRaisesMessage(
            KrakenAccountDataError,
            "Kraken returned invalid order data.",
        ):
            self.service.load(
                account=self.account
            )

    def test_service_has_no_trading_side_effects(self):
        self.service.load(
            account=self.account
        )

        self.adapter.submit_order.assert_not_called()
        self.adapter.cancel_order.assert_not_called()