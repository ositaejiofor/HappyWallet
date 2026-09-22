"""Mocked tests for native public TRX wallet balances."""

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

from django.test import SimpleTestCase

from apps.wallet.services.balance import WalletBalanceService
from apps.wallet.services.tron_balance import TronWalletBalanceService
from apps.wallet.services.wallet_balance import WalletDashboardBalanceService


class TronWalletBalanceTests(SimpleTestCase):
    ADDRESS = "TUoHaVjx7n5xz8LwPRDckgFrDWhMhuSuJM"

    def test_native_trx_balance_uses_common_wallet_dto(self) -> None:
        client = Mock()
        client.get_trx_balance.return_value = Decimal("123.456789")
        service = TronWalletBalanceService(
            network=SimpleNamespace(name="TRON Mainnet"),
            client=client,
        )

        result = service.get_wallet_balance(
            address=self.ADDRESS,
            assets=(),
        )

        self.assertEqual(result.address, self.ADDRESS)
        self.assertEqual(result.native.symbol, "TRX")
        self.assertEqual(result.native.balance, Decimal("123.456789"))
        self.assertEqual(result.native.raw_balance, 123_456_789)
        self.assertEqual(result.native.decimals, 6)
        self.assertEqual(result.tokens, ())
        client.get_trx_balance.assert_called_once_with(self.ADDRESS)

    def test_dashboard_selects_tron_service(self) -> None:
        service = WalletDashboardBalanceService()
        selected = service._get_balance_service_class(
            network=SimpleNamespace(
                slug="tron-mainnet",
                name="TRON Mainnet",
                symbol="TRX",
            )
        )

        self.assertIs(selected, TronWalletBalanceService)

    def test_dashboard_keeps_ethereum_service(self) -> None:
        service = WalletDashboardBalanceService()
        selected = service._get_balance_service_class(
            network=SimpleNamespace(
                slug="ethereum-mainnet",
                name="Ethereum Mainnet",
                symbol="ETH",
            )
        )

        self.assertIs(selected, WalletBalanceService)

    def test_injected_balance_service_keeps_precedence(self) -> None:
        class FakeBalanceService:
            pass

        service = WalletDashboardBalanceService(
            balance_service_class=FakeBalanceService,
        )
        selected = service._get_balance_service_class(
            network=SimpleNamespace(slug="tron-mainnet"),
        )

        self.assertIs(selected, FakeBalanceService)
