from django.db import models


class MarketAsset(models.Model):
    """
    Cryptocurrency/token known to the HappyWallet market system.

    MarketAsset contains relatively stable asset identity/metadata.
    Price information belongs in MarketPrice.
    """

    symbol = models.CharField(
        max_length=32,
        db_index=True,
    )

    name = models.CharField(
        max_length=255,
    )

    coingecko_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
    )

    chain = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
    )

    contract_address = models.CharField(
        max_length=128,
        blank=True,
        default="",
        db_index=True,
    )

    decimals = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
    )

    image_url = models.URLField(
        blank=True,
        default="",
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
        ordering = ["name"]
        indexes = [
            models.Index(fields=["symbol"]),
            models.Index(fields=["chain", "contract_address"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.symbol.upper()})"


class MarketPrice(models.Model):
    """
    Snapshot of market information for an asset.
    """

    asset = models.ForeignKey(
        MarketAsset,
        on_delete=models.CASCADE,
        related_name="prices",
    )

    price_usd = models.DecimalField(
        max_digits=30,
        decimal_places=12,
    )

    market_cap_usd = models.DecimalField(
        max_digits=30,
        decimal_places=2,
        null=True,
        blank=True,
    )

    volume_24h_usd = models.DecimalField(
        max_digits=30,
        decimal_places=2,
        null=True,
        blank=True,
    )

    price_change_24h = models.DecimalField(
        max_digits=12,
        decimal_places=6,
        null=True,
        blank=True,
    )

    circulating_supply = models.DecimalField(
        max_digits=40,
        decimal_places=12,
        null=True,
        blank=True,
    )

    fully_diluted_valuation_usd = models.DecimalField(
        max_digits=30,
        decimal_places=2,
        null=True,
        blank=True,
    )

    captured_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        ordering = ["-captured_at"]
        indexes = [
            models.Index(fields=["asset", "-captured_at"]),
            models.Index(fields=["captured_at"]),
        ]

    def __str__(self):
        return f"{self.asset.symbol.upper()} @ ${self.price_usd}"
    
