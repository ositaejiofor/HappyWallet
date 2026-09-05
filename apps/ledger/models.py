import uuid
from decimal import Decimal

from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import models


class LedgerAccount(models.Model):
    """
    Accounting account belonging to a wallet.

    A wallet can have multiple ledger accounts, for example:
    - USDT
    - USDC
    - BTC
    - ETH
    """

    class AccountType(models.TextChoices):
        ASSET = "asset", "Asset"
        LIABILITY = "liability", "Liability"
        EQUITY = "equity", "Equity"
        REVENUE = "revenue", "Revenue"
        EXPENSE = "expense", "Expense"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ledger_accounts",
    )

    wallet = models.ForeignKey(
        "wallet.Wallet",
        on_delete=models.CASCADE,
        related_name="ledger_accounts",
    )

    asset = models.CharField(
        max_length=20,
        db_index=True,
    )

    account_type = models.CharField(
        max_length=20,
        choices=AccountType.choices,
        default=AccountType.ASSET,
    )

    name = models.CharField(
        max_length=100,
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
        db_table = "ledger_accounts"
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["wallet", "asset", "account_type"],
                name="unique_wallet_asset_account_type",
            ),
        ]
        indexes = [
            models.Index(
                fields=["user", "asset"],
                name="ledger_user_asset_idx",
            ),
            models.Index(
                fields=["wallet", "asset"],
                name="ledger_wallet_asset_idx",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.asset})"


class LedgerEntry(models.Model):
    """
    Immutable accounting entry.

    Every balance-changing operation creates ledger entries.
    """

    class EntryType(models.TextChoices):
        DEBIT = "debit", "Debit"
        CREDIT = "credit", "Credit"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    account = models.ForeignKey(
        LedgerAccount,
        on_delete=models.PROTECT,
        related_name="entries",
    )

    entry_type = models.CharField(
        max_length=10,
        choices=EntryType.choices,
    )

    amount = models.DecimalField(
        max_digits=36,
        decimal_places=18,
        validators=[
            MinValueValidator(Decimal("0.000000000000000001")),
        ],
    )

    reference = models.CharField(
        max_length=100,
        db_index=True,
    )

    description = models.CharField(
        max_length=255,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        db_table = "ledger_entries"
        ordering = ["created_at"]
        indexes = [
            models.Index(
                fields=["account", "created_at"],
                name="ledger_account_created_idx",
            ),
            models.Index(
                fields=["reference"],
                name="ledger_reference_idx",
            ),
        ]

    def __str__(self):
        return (
            f"{self.entry_type.upper()} "
            f"{self.amount} {self.account.asset}"
        )