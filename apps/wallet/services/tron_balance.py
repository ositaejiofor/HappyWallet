"""Read-only TRON balance adapter for the HappyWallet dashboard."""

from __future__ import annotations

from decimal import Decimal
from typing import Iterable

from apps.blockchain.models import Asset, BlockchainNetwork
from apps.transaction.services.networks.tron import (
    TRON_SUN_PER_TRX,
    TronReadOnlyClient,
)

from .balance import NativeBalance, WalletBalance


class TronWalletBalanceService:
    """Adapt public TronGrid balances to the wallet balance DTO contract."""

    def __init__(
        self,
        *,
        network: BlockchainNetwork,
        client: TronReadOnlyClient | None = None,
    ) -> None:
        self.network = network
        self.client = client or TronReadOnlyClient()

    def get_wallet_balance(
        self,
        *,
        address: str,
        assets: Iterable[Asset] = (),
    ) -> WalletBalance:
        # TRC-10/TRC-20 balances are intentionally outside this milestone.
        # Consume no token metadata and return only the native public balance.
        del assets

        balance = self.client.get_trx_balance(address)
        raw_balance = int(balance * TRON_SUN_PER_TRX)

        return WalletBalance(
            address=address.strip(),
            network=(self.network.name or "TRON Mainnet").strip(),
            native=NativeBalance(
                symbol="TRX",
                balance=Decimal(balance),
                raw_balance=raw_balance,
                decimals=6,
            ),
            tokens=(),
        )


__all__ = ["TronWalletBalanceService"]
