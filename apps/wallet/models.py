# apps/wallet/models.py

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class Wallet(models.Model):
    """
    A wallet owned by a HappyWallet user.

    The wallet stores identity and public blockchain metadata.

    Financial balances are handled by the ledger layer.

    Sensitive wallet material such as:
        - mnemonic
        - seed
        - private key

    must never be stored directly on this model.
    """

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        LOCKED = "locked", "Locked"
        SUSPENDED = "suspended", "Suspended"
        ARCHIVED = "archived", "Archived"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="wallets",
    )

    name = models.CharField(
        max_length=100,
        default="Main Wallet",
    )

    address = models.CharField(
        max_length=255,
        blank=True,
        db_index=True,
    )

    network = models.ForeignKey(
        "blockchain.BlockchainNetwork",
        on_delete=models.PROTECT,
        related_name="wallets",
        null=True,
        blank=True,
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.LOCKED,
        db_index=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "wallet_wallet"
        ordering = ["-created_at"]

        constraints = [
            models.UniqueConstraint(
                fields=["user", "name"],
                name="unique_wallet_name_per_user",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} — {self.user.email}"


class WalletAddress(models.Model):
    """
    Blockchain-specific address belonging to a Wallet.

    A wallet may have one active address per blockchain network.

    Only public address information is stored here.
    Private keys and recovery phrases must never be stored.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    wallet = models.ForeignKey(
        Wallet,
        on_delete=models.CASCADE,
        related_name="addresses",
    )

    network = models.ForeignKey(
        "blockchain.BlockchainNetwork",
        on_delete=models.PROTECT,
        related_name="wallet_addresses",
    )

    address = models.CharField(
        max_length=255,
        db_index=True,
    )

    derivation_path = models.CharField(
        max_length=100,
        blank=True,
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
        db_table = "wallet_address"
        ordering = ["-created_at"]

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "wallet",
                    "network",
                ],
                name="unique_wallet_network_address",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.wallet.name} — {self.network.name}"


class WalletVault(models.Model):
    """
    Encrypted wallet recovery material.

    This model stores ONLY encrypted vault bytes.

    Plaintext sensitive material must never be persisted:

        - mnemonic
        - seed
        - private key

    Encryption/decryption is handled by the security layer's
    VaultService.

    The wallet password is also never stored here.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    wallet = models.OneToOneField(
        Wallet,
        on_delete=models.CASCADE,
        related_name="vault",
    )

    encrypted_payload = models.BinaryField()

    version = models.PositiveSmallIntegerField(
        default=1,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "wallet_vault"

    def __str__(self) -> str:
        return f"Vault — {self.wallet.name}"
    
    