"""Restore an existing TRON Shasta wallet into an encrypted USB vault."""

from __future__ import annotations

import getpass

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.usb_manager.detector import USBDetector
from apps.usb_manager.management.commands.provision_tron_testnet_usb import (
    NETWORK_SLUG,
    derive_tron_address,
)
from apps.usb_manager.vault import USBVault, USBVaultError
from apps.security.vault import WalletSecret
from apps.wallet.models import Wallet


class Command(BaseCommand):
    help = (
        "Restore the recovery phrase for an existing TRON Shasta wallet "
        "into a new encrypted USB vault."
    )

    def add_arguments(self, parser):
        parser.add_argument("--device", required=True)
        parser.add_argument("--username", required=True)
        parser.add_argument("--wallet-id", required=True)

    def handle(self, *args, **options):
        device_id = options["device"].strip()
        username = options["username"].strip()
        wallet_id = options["wallet_id"].strip()

        device = USBDetector().find(device_id)
        if device is None:
            raise CommandError("The selected removable USB device was not found.")

        vault = USBVault(device)
        if vault.exists() or vault._has_existing_data():
            raise CommandError(
                "The USB contains an existing or partial HappyWallet vault; "
                "nothing was overwritten."
            )

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError("HappyWallet user was not found.") from exc

        try:
            wallet = Wallet.objects.select_related("network").get(
                pk=wallet_id,
                user=user,
            )
        except (Wallet.DoesNotExist, ValueError) as exc:
            raise CommandError("The selected wallet was not found for this user.") from exc

        if (
            wallet.network is None
            or wallet.network.slug != NETWORK_SLUG
            or not wallet.network.is_testnet
        ):
            raise CommandError("Only an existing TRON Shasta Testnet wallet can be restored.")

        expected_address = wallet.address.strip()
        if not expected_address:
            raise CommandError("The selected wallet does not have a public address.")

        confirmation = input(
            "Type RESTORE to rebuild this wallet's encrypted USB vault: "
        ).strip()
        if confirmation != "RESTORE":
            raise CommandError("Cancelled; no USB vault was created.")

        mnemonic = getpass.getpass(
            "Enter the 24 recovery words (input hidden): "
        ).strip()
        password = ""
        password_again = ""
        secret = None
        created = False

        try:
            if len(mnemonic.split()) != 24:
                raise CommandError(
                    "Recovery phrase must contain exactly 24 words; nothing was written."
                )

            try:
                derived_address = derive_tron_address(mnemonic)
            except (ValueError, TypeError) as exc:
                raise CommandError(
                    "Recovery phrase is invalid; nothing was written."
                ) from exc

            if derived_address != expected_address:
                raise CommandError(
                    "Recovery phrase does not control the selected wallet address; "
                    "nothing was written."
                )

            password = getpass.getpass("New USB vault password: ")
            password_again = getpass.getpass("Confirm USB vault password: ")
            if password != password_again:
                raise CommandError("Passwords do not match; nothing was written.")

            secret = WalletSecret(mnemonic=mnemonic)
            try:
                metadata = vault.create(
                    secret=secret,
                    password=password,
                    wallet_name=wallet.name,
                    network=NETWORK_SLUG,
                )
                created = True

                recovered = vault.unlock(password)
                try:
                    recovered_address = derive_tron_address(
                        recovered.mnemonic or ""
                    )
                finally:
                    del recovered

                if recovered_address != expected_address:
                    raise CommandError(
                        "USB vault verification failed; the new vault was removed."
                    )
            except (USBVaultError, ValueError, TypeError) as exc:
                raise CommandError(str(exc)) from exc

        except Exception:
            if created:
                try:
                    vault.remove_vault()
                except USBVaultError:
                    self.stderr.write(
                        self.style.ERROR(
                            "Recovery failed and automatic vault cleanup also failed. "
                            "Do not use this USB vault until it is inspected."
                        )
                    )
            raise
        finally:
            if secret is not None:
                del secret
            del mnemonic
            del password
            del password_again

        self.stdout.write(
            self.style.SUCCESS("Encrypted USB wallet restored and verified.")
        )
        self.stdout.write(f"Wallet ID: {wallet.pk}")
        self.stdout.write(f"TRON Shasta address: {expected_address}")
        self.stdout.write(f"USB vault ID: {metadata.vault_id}")
        self.stdout.write(
            self.style.WARNING(
                "The recovery phrase was not displayed or stored in the database."
            )
        )
