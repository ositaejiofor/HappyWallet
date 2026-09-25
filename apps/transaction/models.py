"""
HappyWallet Transaction Models.

Stores transaction metadata and lifecycle state.

Private keys, mnemonics, and raw secret material must NEVER be stored
in these models.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class Transaction(models.Model):
    """Represents a blockchain transaction managed by HappyWallet."""

    class Status(models.TextChoices):
        CREATED = "created", "Created"
        BUILT = "built", "Built"
        SIGNED = "signed", "Signed"
        BROADCASTING = "broadcasting", "Broadcasting"
        BROADCAST = "broadcast", "Broadcast"
        CONFIRMED = "confirmed", "Confirmed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class TransactionType(models.TextChoices):
        TRANSFER = "transfer", "Transfer"
        TOKEN_TRANSFER = "token_transfer", "Token Transfer"
        CONTRACT = "contract", "Contract"
        SWAP = "swap", "Swap"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="transactions",
    )

    wallet = models.ForeignKey(
        "wallet.Wallet",
        on_delete=models.PROTECT,
        related_name="transactions",
    )

    network = models.ForeignKey(
        "blockchain.BlockchainNetwork",
        on_delete=models.PROTECT,
        related_name="transactions",
    )

    transaction_type = models.CharField(
        max_length=30,
        choices=TransactionType.choices,
        default=TransactionType.TRANSFER,
        db_index=True,
    )

    status = models.CharField(
        max_length=30,
        choices=Status.choices,
        default=Status.CREATED,
        db_index=True,
    )

    asset = models.CharField(
        max_length=20,
        db_index=True,
    )

    sender = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
    )

    recipient = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
    )

    amount = models.DecimalField(
        max_digits=36,
        decimal_places=18,
        null=True,
        blank=True,
    )

    nonce = models.PositiveBigIntegerField(
        null=True,
        blank=True,
    )

    chain_id = models.PositiveBigIntegerField(
        null=True,
        blank=True,
    )

    payload_hash = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
    )

    signature = models.TextField(
        blank=True,
    )

    transaction_hash = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
    )

    error_code = models.CharField(
        max_length=100,
        blank=True,
    )

    error_message = models.TextField(
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    signed_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    broadcast_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    confirmed_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "transactions"
        ordering = ["-created_at"]

        indexes = [
            models.Index(
                fields=["user", "created_at"],
                name="tx_user_created_idx",
            ),
            models.Index(
                fields=["wallet", "created_at"],
                name="tx_wallet_created_idx",
            ),
            models.Index(
                fields=["network", "status"],
                name="tx_network_status_idx",
            ),
            models.Index(
                fields=["transaction_hash"],
                name="tx_hash_idx",
            ),
            models.Index(
                fields=["payload_hash"],
                name="tx_payload_hash_idx",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.transaction_type} "
            f"{self.asset} "
            f"{self.status}"
        )


class TronSendIntent(models.Model):
    """Durable, unsigned TRON send request with replay protection."""

    class Status(models.TextChoices):
        PREPARED = "prepared", "Prepared"
        BROADCASTING = "broadcasting", "Broadcasting"
        SUBMITTED = "submitted", "Submitted"
        OUTCOME_UNKNOWN = "outcome_unknown", "Outcome unknown"
        REJECTED = "rejected", "Rejected"
        EXPIRED = "expired", "Expired"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tron_send_intents",
    )
    wallet = models.ForeignKey(
        "wallet.Wallet",
        on_delete=models.PROTECT,
        related_name="tron_send_intents",
    )
    network = models.ForeignKey(
        "blockchain.BlockchainNetwork",
        on_delete=models.PROTECT,
        related_name="tron_send_intents",
    )
    idempotency_key = models.UUIDField()
    status = models.CharField(
        max_length=24,
        choices=Status.choices,
        default=Status.PREPARED,
        db_index=True,
    )
    asset = models.CharField(max_length=20)
    sender = models.CharField(max_length=64)
    recipient = models.CharField(max_length=64)
    amount = models.DecimalField(max_digits=36, decimal_places=18)
    estimated_fee_trx = models.DecimalField(max_digits=24, decimal_places=6)
    estimated_energy = models.PositiveBigIntegerField(default=0)
    unsigned_transaction = models.JSONField()
    transaction_hash = models.CharField(max_length=64, blank=True, db_index=True)
    error_code = models.CharField(max_length=80, blank=True)
    error_message = models.CharField(max_length=255, blank=True)
    expires_at = models.DateTimeField()
    submitted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tron_send_intents"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "idempotency_key"],
                name="unique_tron_send_idempotency",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.asset} {self.amount} ({self.status})"
