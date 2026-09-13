from __future__ import annotations

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class Token(models.Model):
    """
    Represents a token discovered by the HappyWallet Token Scanner.

    Only public blockchain and analytical information is stored.

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

    # -------------------------------------------------------------------------
    # Current observed market metrics
    # -------------------------------------------------------------------------

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

    # -------------------------------------------------------------------------
    # Contract risk observations
    # -------------------------------------------------------------------------

    contract_verified = models.BooleanField(
        default=False,
    )

    unlimited_mint_detected = models.BooleanField(
        default=False,
    )

    blacklist_detected = models.BooleanField(
        default=False,
    )

    # The scanner currently does not have a dedicated liquidity-lock
    # verification provider, so this must never be set to True speculatively.
    liquidity_locked = models.BooleanField(
        default=False,
    )

    # -------------------------------------------------------------------------
    # Current observed risk
    # -------------------------------------------------------------------------

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
    Immutable historical snapshot of public on-chain observations.

    Every scan records not only the metrics observed, but also the blockchain
    observation window used to produce those metrics.

    This distinction is important:

        observed evidence != complete historical truth

    A LIMITED observation window must not be interpreted as a complete
    representation of token history.
    """

    class ObservationQuality(models.TextChoices):
        """
        Describes the breadth of the blockchain observation window.

        These values describe observation coverage, not token safety.
        """

        LIMITED = "LIMITED", "Limited"
        STANDARD = "STANDARD", "Standard"
        EXTENDED = "EXTENDED", "Extended"

    token = models.ForeignKey(
        Token,
        on_delete=models.CASCADE,
        related_name="scans",
    )

    scanned_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    # -------------------------------------------------------------------------
    # Blockchain observation window
    # -------------------------------------------------------------------------

    from_block = models.PositiveBigIntegerField(
        null=True,
        blank=True,
    )

    to_block = models.PositiveBigIntegerField(
        null=True,
        blank=True,
    )

    observation_block_count = models.PositiveBigIntegerField(
        null=True,
        blank=True,
    )

    observation_quality = models.CharField(
        max_length=20,
        choices=ObservationQuality.choices,
        blank=True,
        default="",
    )

    # -------------------------------------------------------------------------
    # Observed market metrics
    # -------------------------------------------------------------------------

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

    # -------------------------------------------------------------------------
    # Observed risk
    # -------------------------------------------------------------------------

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
            models.Index(
                fields=["observation_quality", "-scanned_at"],
            ),
            models.Index(
                fields=["from_block", "to_block"],
            ),
        ]

    def __str__(self) -> str:
        token_name = (
            self.token.symbol
            or self.token.contract_address
        )

        return (
            f"{token_name} "
            f"scan @ {self.scanned_at:%Y-%m-%d %H:%M:%S}"
        )

    @property
    def has_block_range(self) -> bool:
        """Return whether this snapshot has a concrete block range."""

        return (
            self.from_block is not None
            and self.to_block is not None
        )

    @property
    def block_range(self) -> str:
        """Return a human-readable observation range."""

        if not self.has_block_range:
            return "Unknown"

        return (
            f"{self.from_block:,} → "
            f"{self.to_block:,}"
        )


class TokenAlert(models.Model):
    """
    Scanner alert generated from observed token conditions.

    Alerts are informational only.

    They NEVER:
        - buy tokens
        - sell tokens
        - sign transactions
        - submit transactions
        - execute swaps
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
        return (
            f"{self.get_severity_display()}: "
            f"{self.title}"
        )
