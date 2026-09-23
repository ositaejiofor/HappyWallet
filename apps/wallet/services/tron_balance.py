"""Read-only TRON balance adapter for the HappyWallet dashboard."""

from __future__ import annotations

from decimal import Decimal
from typing import Iterable

from apps.blockchain.models import Asset, BlockchainNetwork
from apps.transaction.services.networks.tron import (
    TRON_SUN_PER_TRX,
    TronReadOnlyClient,
)

from .balance import NativeBalance, TokenBalance, WalletBalance


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
        balance = self.client.get_trx_balance(address)
        raw_balance = int(balance * TRON_SUN_PER_TRX)
        tokens: list[TokenBalance] = []

        for asset in assets:
            if (
                asset.is_native
                or asset.token_standard != Asset.TokenStandard.TRC20
                or not asset.contract_address
            ):
                continue

            token_balance = self.client.get_trc20_balance(
                address,
                contract_address=asset.contract_address.strip(),
                decimals=asset.decimals,
            )
            token_raw_balance = int(
                token_balance * (Decimal(10) ** asset.decimals)
            )
            tokens.append(
                TokenBalance(
                    address=asset.contract_address.strip(),
                    name=asset.name.strip(),
                    symbol=asset.symbol.strip().upper(),
                    balance=token_balance,
                    raw_balance=token_raw_balance,
                    decimals=asset.decimals,
                    asset_id=str(asset.pk),
                )
            )

        return WalletBalance(
            address=address.strip(),
            network=(self.network.name or "TRON Mainnet").strip(),
            native=NativeBalance(
                symbol="TRX",
                balance=Decimal(balance),
                raw_balance=raw_balance,
                decimals=6,
            ),
            tokens=tuple(tokens),
        )


__all__ = ["TronWalletBalanceService"]
