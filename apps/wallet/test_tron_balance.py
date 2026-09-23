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

    def test_configured_trc20_usdt_balance_is_returned_separately(self) -> None:
        client = Mock()
        client.get_trx_balance.return_value = Decimal("2")
        client.get_trc20_balance.return_value = Decimal("125.500001")
        asset = SimpleNamespace(
            pk="token-id",
            name="Tether USD",
            symbol="USDT",
            token_standard="trc20",
            contract_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
            decimals=6,
            is_native=False,
        )
        service = TronWalletBalanceService(
            network=SimpleNamespace(name="TRON Mainnet"),
            client=client,
        )

        result = service.get_wallet_balance(
            address=self.ADDRESS,
            assets=(asset,),
        )

        self.assertEqual(result.native.balance, Decimal("2"))
        self.assertEqual(len(result.tokens), 1)
        self.assertEqual(result.tokens[0].symbol, "USDT")
        self.assertEqual(result.tokens[0].balance, Decimal("125.500001"))
        self.assertEqual(result.tokens[0].raw_balance, 125_500_001)
        client.get_trc20_balance.assert_called_once_with(
            self.ADDRESS,
            contract_address=asset.contract_address,
            decimals=6,
        )

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
