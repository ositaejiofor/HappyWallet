"""
HappyWallet trading models.

The trading subsystem is deliberately separated from wallet signing.

These models represent trading intent and execution records.
They do NOT contain:

    - private keys
    - seed phrases
    - mnemonics
    - wallet encryption material
    - signing material

Real blockchain execution must happen through a dedicated execution
boundary after explicit confirmation and policy validation.
"""

from decimal import Decimal

from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import models


class TradingAccount(models.Model):
    """
    Paper/simulation trading account.

    A TradingAccount is intentionally separate from a blockchain Wallet.
    This prevents simulated trading balances from being confused with
    real wallet balances.
    """

    class Mode(models.TextChoices):
        PAPER = "paper", "Paper Trading"
        LIVE = "live", "Live Trading"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="trading_account",
    )

    name = models.CharField(
        max_length=100,
        default="Main Trading Account",
    )

    mode = models.CharField(
        max_length=20,
        choices=Mode.choices,
        default=Mode.PAPER,
    )

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} - {self.user}"

    @property
    def is_paper(self):
        return self.mode == self.Mode.PAPER


class TradingBalance(models.Model):
    """
    Balance belonging to a TradingAccount.

    These are trading balances, not blockchain wallet balances.
    """

    account = models.ForeignKey(
        TradingAccount,
        on_delete=models.CASCADE,
        related_name="balances",
    )

    asset = models.ForeignKey(
        "market.MarketAsset",
        on_delete=models.PROTECT,
        related_name="trading_balances",
    )

    available = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        default=Decimal("0"),
        validators=[MinValueValidator(Decimal("0"))],
    )

    locked = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        default=Decimal("0"),
        validators=[MinValueValidator(Decimal("0"))],
    )

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["account", "asset"],
                name="unique_trading_account_asset",
            ),
        ]

        indexes = [
            models.Index(
                fields=["account", "asset"],
            ),
        ]

    def __str__(self):
        return (
            f"{self.account} - "
            f"{self.asset.symbol.upper()} - "
            f"{self.available}"
        )

    @property
    def total(self):
        return self.available + self.locked


class TradingPair(models.Model):
    """
    Tradable market pair.

    Examples:

        BTC / USDT
        ETH / USDT
        ETH / BTC
    """

    base_asset = models.ForeignKey(
        "market.MarketAsset",
        on_delete=models.PROTECT,
        related_name="base_trading_pairs",
    )

    quote_asset = models.ForeignKey(
        "market.MarketAsset",
        on_delete=models.PROTECT,
        related_name="quote_trading_pairs",
    )

    symbol = models.CharField(
        max_length=80,
        unique=True,
        db_index=True,
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
    )

    min_order_quantity = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        default=Decimal("0.00000001"),
        validators=[MinValueValidator(Decimal("0"))],
    )

    max_order_quantity = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0"))],
    )

    price_precision = models.PositiveSmallIntegerField(
        default=8,
    )

    quantity_precision = models.PositiveSmallIntegerField(
        default=8,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["symbol"]

        constraints = [
            models.UniqueConstraint(
                fields=["base_asset", "quote_asset"],
                name="unique_trading_pair",
            ),
        ]

    def __str__(self):
        return self.symbol


class Order(models.Model):
    """
    Trading order.

    An Order represents user intent.

    It does not itself contain signing material or blockchain credentials.
    """

    class Side(models.TextChoices):
        BUY = "buy", "Buy"
        SELL = "sell", "Sell"

    class OrderType(models.TextChoices):
        MARKET = "market", "Market"
        LIMIT = "limit", "Limit"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SUBMITTING = "submitting", "Submitting"
        UNKNOWN = "unknown", "Unknown"
        OPEN = "open", "Open"
        PARTIALLY_FILLED = "partially_filled", "Partially Filled"
        FILLED = "filled", "Filled"
        CANCELLED = "cancelled", "Cancelled"
        REJECTED = "rejected", "Rejected"
        FAILED = "failed", "Failed"

    account = models.ForeignKey(
        TradingAccount,
        on_delete=models.PROTECT,
        related_name="orders",
    )

    pair = models.ForeignKey(
        TradingPair,
        on_delete=models.PROTECT,
        related_name="orders",
    )

    client_order_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
    )

    side = models.CharField(
        max_length=10,
        choices=Side.choices,
    )

    order_type = models.CharField(
        max_length=10,
        choices=OrderType.choices,
    )

    quantity = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        validators=[MinValueValidator(Decimal("0"))],
    )

    limit_price = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0"))],
    )

    filled_quantity = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        default=Decimal("0"),
        validators=[MinValueValidator(Decimal("0"))],
    )

    average_fill_price = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0"))],
    )

    status = models.CharField(
        max_length=30,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )

    rejection_reason = models.TextField(
        blank=True,
        default="",
    )

    exchange_order_id = models.CharField(
        max_length=128,
        blank=True,
        default="",
        db_index=True,
    )

    exchange_client_order_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
    )

    submission_error = models.TextField(
        blank=True,
        default="",
    )

    submitted_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

        indexes = [
            models.Index(
                fields=["account", "-created_at"],
            ),
            models.Index(
                fields=["pair", "status"],
            ),
        ]

    def __str__(self):
        return (
            f"{self.side.upper()} "
            f"{self.quantity} "
            f"{self.pair.symbol}"
        )

    @property
    def remaining_quantity(self):
        return max(
            Decimal("0"),
            self.quantity - self.filled_quantity,
        )

    @property
    def is_complete(self):
        return self.status == self.Status.FILLED


class Trade(models.Model):
    """
    Actual execution/fill belonging to an Order.
    """

    order = models.ForeignKey(
        Order,
        on_delete=models.PROTECT,
        related_name="trades",
    )

    execution_id = models.CharField(
        max_length=128,
        unique=True,
        db_index=True,
    )

    quantity = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        validators=[MinValueValidator(Decimal("0"))],
    )

    price = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        validators=[MinValueValidator(Decimal("0"))],
    )

    fee = models.DecimalField(
        max_digits=40,
        decimal_places=18,
        default=Decimal("0"),
        validators=[MinValueValidator(Decimal("0"))],
    )

    fee_asset = models.ForeignKey(
        "market.MarketAsset",
        on_delete=models.PROTECT,
        related_name="trading_fees",
        null=True,
        blank=True,
    )

    executed_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        ordering = ["-executed_at"]

        indexes = [
            models.Index(
                fields=["order", "-executed_at"],
            ),
        ]

    def __str__(self):
        return (
            f"{self.execution_id}: "
            f"{self.quantity} @ {self.price}"
        )

    @property
    def notional_value(self):
        quantity = self.quantity or Decimal("0")
        price = self.price or Decimal("0")
        return quantity * price
