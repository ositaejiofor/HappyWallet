"""
HappyWallet Wallet Vault Persistence Service.

This service connects the wallet domain to the security vault layer.

Responsibilities
----------------
- Create encrypted wallet vault records.
- Replace encrypted vault payloads.
- Load encrypted vault payloads.
- Open wallet secrets using a supplied password.
- Lock/unlock wallet state.

Security
--------
- Plaintext mnemonic/private-key material is never persisted.
- WalletSecret exists only in memory.
- WalletVault.encrypted_payload contains encrypted bytes only.
- Cryptographic operations are delegated to VaultService.
"""

from __future__ import annotations

from django.db import transaction

from apps.security.vault import (
    VaultService,
    WalletSecret,
)

from apps.wallet.models import Wallet, WalletVault


class WalletVaultService:
    """
    Application service for encrypted wallet-vault persistence.
    """

    def __init__(
        self,
        vault_service: VaultService | None = None,
    ) -> None:
        self.vault = (
            vault_service
            if vault_service is not None
            else VaultService()
        )

    # ==================================================================
    # GET VAULT
    # ==================================================================

    @staticmethod
    def get_vault(
        wallet: Wallet,
    ) -> WalletVault | None:
        """
        Return the wallet's encrypted vault record.
        """

        if wallet is None:
            return None

        return (
            WalletVault.objects
            .filter(wallet=wallet)
            .first()
        )

    # ==================================================================
    # CREATE / REPLACE VAULT
    # ==================================================================

    @transaction.atomic
    def save_secret(
        self,
        *,
        wallet: Wallet,
        secret: WalletSecret,
        password: str,
    ) -> WalletVault:
        """
        Encrypt and persist wallet secret material.

        Plaintext secrets are never written to the database.
        """

        if not isinstance(wallet, Wallet):
            raise ValueError(
                "A valid Wallet instance is required."
            )

        if not isinstance(secret, WalletSecret):
            raise TypeError(
                "secret must be a WalletSecret."
            )

        encrypted_payload = self.vault.create_vault(
            secret,
            password,
        )

        vault_record, _created = (
            WalletVault.objects.update_or_create(
                wallet=wallet,
                defaults={
                    "encrypted_payload": encrypted_payload,
                    "version": self.vault.VERSION,
                },
            )
        )

        return vault_record

    # ==================================================================
    # OPEN VAULT
    # ==================================================================

    def open_secret(
        self,
        *,
        wallet: Wallet,
        password: str,
    ) -> WalletSecret:
        """
        Decrypt and return the wallet secret.

        The returned WalletSecret is sensitive and must remain
        in memory only.
        """

        vault_record = self.get_vault(wallet)

        if vault_record is None:
            raise ValueError(
                "Wallet does not have an encrypted vault."
            )

        return self.vault.open_vault(
            vault_record.encrypted_payload,
            password,
        )

    # ==================================================================
    # VALIDATE VAULT
    # ==================================================================

    def validate(
        self,
        *,
        wallet: Wallet,
    ) -> None:
        """
        Validate the stored encrypted vault structure.
        """

        vault_record = self.get_vault(wallet)

        if vault_record is None:
            raise ValueError(
                "Wallet does not have an encrypted vault."
            )

        self.vault.validate_vault(
            vault_record.encrypted_payload,
        )

    # ==================================================================
    # DELETE VAULT
    # ==================================================================

    @transaction.atomic
    def delete_vault(
        self,
        *,
        wallet: Wallet,
    ) -> bool:
        """
        Delete the encrypted vault record.

        This does not delete the Wallet or WalletAddress.
        """

        deleted, _details = (
            WalletVault.objects
            .filter(wallet=wallet)
            .delete()
        )

        return deleted > 0


# ======================================================================
# DEFAULT SERVICE
# ======================================================================

wallet_vault_service = WalletVaultService()
