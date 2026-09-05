# apps/blockchain/models.py

from __future__ import annotations

import uuid

from django.core.validators import (
    MaxValueValidator,
    MinValueValidator,
)
from django.db import models


class BlockchainNetwork(models.Model):
    """
    Represents a supported blockchain network.

    Examples:
        Ethereum Mainnet
        Bitcoin Mainnet
        Tron Mainnet
        Polygon Mainnet

    Security:
        RPC credentials are NOT stored here.
        Private RPC endpoints are resolved from environment
        configuration through the blockchain service layer.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    name = models.CharField(
        max_length=100,
        unique=True,
    )

    slug = models.SlugField(
        max_length=100,
        unique=True,
    )

    symbol = models.CharField(
        max_length=20,
    )

    chain_id = models.PositiveBigIntegerField(
        null=True,
        blank=True,
    )

    # ----------------------------------------------------------
    # Public network metadata
    # ----------------------------------------------------------
    #
    # This field is retained for database compatibility.
    #
    # Do NOT store authenticated/private RPC URLs here.
    #
    # Runtime RPC configuration is resolved from:
    #
    #     ETHEREUM_RPC_URL
    #     BITCOIN_RPC_URL
    #     TRON_RPC_URL
    #
    rpc_url = models.URLField(
        blank=True,
    )

    explorer_url = models.URLField(
        blank=True,
    )

    is_testnet = models.BooleanField(
        default=False,
        db_index=True,
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "blockchain_networks"

        ordering = [
            "name",
        ]

        verbose_name = "Blockchain Network"

        verbose_name_plural = "Blockchain Networks"

    def __str__(self) -> str:
        return f"{self.name} ({self.symbol})"


class Asset(models.Model):
    """
    Represents a blockchain asset or token.

    Examples:
        ETH on Ethereum
        BTC on Bitcoin
        USDT on Ethereum
        USDT on Tron
        USDC on Polygon
    """

    class TokenStandard(models.TextChoices):
        NATIVE = "native", "Native"
        ERC20 = "erc20", "ERC-20"
        TRC20 = "trc20", "TRC-20"
        BEP20 = "bep20", "BEP-20"
        SPL = "spl", "SPL"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    network = models.ForeignKey(
        BlockchainNetwork,
        on_delete=models.PROTECT,
        related_name="assets",
    )

    symbol = models.CharField(
        max_length=20,
    )

    name = models.CharField(
        max_length=100,
    )

    token_standard = models.CharField(
        max_length=20,
        choices=TokenStandard.choices,
        default=TokenStandard.NATIVE,
    )

    contract_address = models.CharField(
        max_length=255,
        blank=True,
    )

    decimals = models.PositiveSmallIntegerField(
        validators=[
            MinValueValidator(0),
            MaxValueValidator(36),
        ],
        default=18,
    )

    is_native = models.BooleanField(
        default=False,
    )

    is_active = models.BooleanField(
        default=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "blockchain_assets"

        ordering = [
            "network",
            "symbol",
        ]

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "network",
                    "symbol",
                    "contract_address",
                ],
                name="unique_network_asset_contract",
            ),
        ]

        indexes = [
            models.Index(
                fields=[
                    "network",
                    "symbol",
                ],
                name="asset_network_symbol_idx",
            ),
            models.Index(
                fields=[
                    "contract_address",
                ],
                name="asset_contract_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.symbol} ({self.network.name})"


class AssetMarketMapping(models.Model):
    """
    Maps a market-data asset to a specific blockchain asset.

    MarketAsset represents market identity, while Asset represents
    the concrete network-specific blockchain asset.

    Example:

        USDT (MarketAsset)
            -> USDT / Ethereum / ERC-20
            -> USDT / Tron / TRC-20
            -> USDT / BNB Chain / BEP-20
    """

    market_asset = models.ForeignKey(
        "market.MarketAsset",
        on_delete=models.CASCADE,
        related_name="blockchain_mappings",
    )

    blockchain_asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="market_mappings",
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "asset_market_mappings"

        ordering = [
            "market_asset",
            "blockchain_asset",
        ]

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "market_asset",
                    "blockchain_asset",
                ],
                name="unique_asset_market_mapping",
            ),
        ]

        indexes = [
            models.Index(
                fields=[
                    "market_asset",
                    "is_active",
                ],
                name="mapping_market_active_idx",
            ),
            models.Index(
                fields=[
                    "blockchain_asset",
                    "is_active",
                ],
                name="mapping_blockchain_active_idx",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.market_asset.symbol.upper()} -> "
            f"{self.blockchain_asset.symbol.upper()} "
            f"({self.blockchain_asset.network.name})"
        )
        
        
        