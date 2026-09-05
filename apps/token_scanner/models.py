from __future__ import annotations

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class Token(models.Model):
    """
    Represents a token discovered by the HappyWallet Token Scanner.

    This model stores analytical/public blockchain information only.

    NEVER store:
        - private keys
        - seed phrases
        - mnemonics
        - wallet passwords
        - signing material
    """

    chain = models.CharField(
        max_length=50,
        default="ethereum",
    )

    contract_address = models.CharField(
        max_length=42,
        unique=True,
        db_index=True,
    )

    name = models.CharField(
        max_length=255,
        blank=True,
    )

    symbol = models.CharField(
        max_length=50,
        blank=True,
    )

    decimals = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
    )

    creation_time = models.DateTimeField(
        null=True,
        blank=True,
    )

    liquidity_usd = models.DecimalField(
        max_digits=30,
        decimal_places=2,
        null=True,
        blank=True,
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

    holder_count = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    top_10_holder_percentage = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        null=True,
        blank=True,
    )

    buy_count_24h = models.PositiveIntegerField(
        default=0,
    )

    sell_count_24h = models.PositiveIntegerField(
        default=0,
    )

    contract_verified = models.BooleanField(
        default=False,
    )

    unlimited_mint_detected = models.BooleanField(
        default=False,
    )

    blacklist_detected = models.BooleanField(
        default=False,
    )

    liquidity_locked = models.BooleanField(
        default=False,
    )

    risk_score = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(100),
        ],
    )

    first_seen_at = models.DateTimeField(
        auto_now_add=True,
    )

    last_scanned_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["-first_seen_at"]
        indexes = [
            models.Index(
                fields=["chain", "first_seen_at"],
            ),
            models.Index(
                fields=["risk_score"],
            ),
        ]

    def __str__(self) -> str:
        if self.symbol:
            return f"{self.symbol} ({self.contract_address})"

        return self.contract_address


class TokenScan(models.Model):
    """
    Historical snapshot of a token's public on-chain metrics.

    Each scan represents what HappyWallet observed at a particular
    point in time.
    """

    token = models.ForeignKey(
        Token,
        on_delete=models.CASCADE,
        related_name="scans",
    )

    scanned_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    liquidity_usd = models.DecimalField(
        max_digits=30,
        decimal_places=2,
        null=True,
        blank=True,
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

    holder_count = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    top_10_holder_percentage = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(100),
        ],
    )

    buy_count_24h = models.PositiveIntegerField(
        default=0,
    )

    sell_count_24h = models.PositiveIntegerField(
        default=0,
    )

    risk_score = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(100),
        ],
    )

    class Meta:
        ordering = ["-scanned_at"]
        indexes = [
            models.Index(
                fields=["token", "-scanned_at"],
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.token.symbol or self.token.contract_address} "
            f"scan @ {self.scanned_at:%Y-%m-%d %H:%M:%S}"
        )


class TokenAlert(models.Model):
    """
    Scanner alert generated from observed token conditions.

    Alerts are informational. They do not execute trades.
    """

    class AlertType(models.TextChoices):
        NEW_TOKEN = "new_token", "New Token"
        HOLDER_GROWTH = "holder_growth", "Holder Growth"
        VOLUME_SPIKE = "volume_spike", "Volume Spike"
        LIQUIDITY_CHANGE = "liquidity_change", "Liquidity Change"
        DEMAND_INCREASE = "demand_increase", "Demand Increase"
        RISK_CHANGE = "risk_change", "Risk Score Change"
        CONTRACT_WARNING = "contract_warning", "Contract Warning"
        LIQUIDITY_WARNING = "liquidity_warning", "Liquidity Warning"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    token = models.ForeignKey(
        Token,
        on_delete=models.CASCADE,
        related_name="alerts",
    )

    alert_type = models.CharField(
        max_length=50,
        choices=AlertType.choices,
    )

    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.INFO,
    )

    title = models.CharField(
        max_length=255,
    )

    message = models.TextField()

    data = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    acknowledged_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["token", "-created_at"],
            ),
            models.Index(
                fields=["severity", "-created_at"],
            ),
        ]

    def __str__(self) -> str:
        return f"{self.get_severity_display()}: {self.title}"