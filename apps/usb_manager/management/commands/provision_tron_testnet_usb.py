"""Provision a new encrypted, USB-backed TRON Shasta wallet."""

from __future__ import annotations

import getpass

from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.blockchain.models import BlockchainNetwork
from apps.security.vault import WalletSecret
from apps.transaction.services.tron_send import private_key_to_address
from apps.usb_manager.detector import USBDetector
from apps.usb_manager.vault import USBVault, USBVaultError
from apps.wallet.models import Wallet, WalletAddress
from apps.wallet.services.hd_wallet import HDWalletService


DERIVATION_PATH = "m/44'/195'/0'/0/0"
NETWORK_SLUG = "tron-shasta-testnet"


def derive_tron_address(mnemonic: str) -> str:
    """Derive the first standard BIP-44 TRON address."""

    seed = Bip39SeedGenerator(mnemonic).Generate()
    try:
        node = (
            Bip44.FromSeed(seed, Bip44Coins.TRON)
            .Purpose()
            .Coin()
            .Account(0)
            .Change(Bip44Changes.CHAIN_EXT)
            .AddressIndex(0)
        )
        key = node.PrivateKey().Raw().ToBytes()
        try:
            return private_key_to_address(key)
        finally:
            del key
    finally:
        del seed


class Command(BaseCommand):
    help = "Create a new Shasta wallet whose recovery phrase is encrypted on USB."

    def add_arguments(self, parser):
        parser.add_argument("--device", required=True)
        parser.add_argument("--username", required=True)
        parser.add_argument(
            "--wallet-name",
            default="TRON USB Shasta Wallet",
        )

    def handle(self, *args, **options):
        device_id = options["device"].strip()
        username = options["username"].strip()
        wallet_name = options["wallet_name"].strip()
        if not wallet_name:
            raise CommandError("Wallet name cannot be empty.")

        device = USBDetector().find(device_id)
        if device is None:
            raise CommandError("The selected removable USB device was not found.")

        vault = USBVault(device)
        if vault.exists() or vault._has_existing_data():
            raise CommandError(
                "The USB contains an existing or partial HappyWallet vault; nothing was overwritten."
            )

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError("HappyWallet user was not found.") from exc

        try:
            network = BlockchainNetwork.objects.get(
                slug=NETWORK_SLUG,
                is_testnet=True,
                is_active=True,
            )
        except BlockchainNetwork.DoesNotExist as exc:
            raise CommandError(
                "TRON Shasta Testnet is not provisioned. Run provision_networks first."
            ) from exc

        if Wallet.objects.filter(user=user, name=wallet_name).exists():
            raise CommandError("A wallet with this name already exists for the user.")

        confirmation = input(
            "Type CREATE to generate a new recovery phrase and encrypted USB vault: "
        ).strip()
        if confirmation != "CREATE":
            raise CommandError("Cancelled; no wallet or vault was created.")

        password = getpass.getpass("New USB vault password: ")
        password_again = getpass.getpass("Confirm USB vault password: ")
        if password != password_again:
            raise CommandError("Passwords do not match; nothing was created.")

        mnemonic = HDWalletService.generate_mnemonic(words=24)
        secret = WalletSecret(mnemonic=mnemonic)
        address = derive_tron_address(mnemonic)

        try:
            metadata = vault.create(
                secret=secret,
                password=password,
                wallet_name=wallet_name,
                network=NETWORK_SLUG,
            )
            recovered = vault.unlock(password)
            try:
                recovered_address = derive_tron_address(recovered.mnemonic or "")
            finally:
                del recovered
            if recovered_address != address:
                raise CommandError("USB vault verification failed.")
        except (USBVaultError, ValueError, TypeError) as exc:
            raise CommandError(str(exc)) from exc

        with transaction.atomic():
            wallet = Wallet.objects.create(
                user=user,
                name=wallet_name,
                address=address,
                network=network,
                status=Wallet.Status.ACTIVE,
            )
            WalletAddress.objects.create(
                wallet=wallet,
                network=network,
                address=address,
                derivation_path=DERIVATION_PATH,
                is_active=True,
            )

        self.stdout.write(self.style.SUCCESS("Encrypted USB wallet created and verified."))
        self.stdout.write(f"Wallet ID: {wallet.pk}")
        self.stdout.write(f"TRON Shasta address: {address}")
        self.stdout.write(f"USB vault ID: {metadata.vault_id}")
        self.stdout.write("")
        self.stdout.write(self.style.WARNING("WRITE THESE 24 WORDS ON PAPER NOW."))
        self.stdout.write(self.style.WARNING("Never photograph, upload, email, or paste them into chat."))
        self.stdout.write(mnemonic)
        self.stdout.write("")
        self.stdout.write(self.style.WARNING("After recording them, clear the terminal screen."))

        del secret
        del mnemonic
        del password
        del password_again
