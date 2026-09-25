"""Safety tests for TRON testnet USB-wallet provisioning."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase

from apps.blockchain.models import BlockchainNetwork
from apps.usb_manager.detector import USBDevice
from apps.usb_manager.vault import USBVault
from apps.wallet.models import Wallet, WalletAddress, WalletVault


class ProvisionTronUSBTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="usb-test@example.com",
            username="usb-test",
            password="not-the-vault-password",
        )
        self.network = BlockchainNetwork.objects.create(
            name="TRON Shasta Testnet",
            slug="tron-shasta-testnet",
            symbol="TRX",
            is_testnet=True,
            is_active=True,
        )
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.device = USBDevice(
            device_id="TEST:",
            mount_path=Path(self.temp_dir.name),
        )

    def run_command(self):
        with (
            patch(
                "apps.usb_manager.management.commands.provision_tron_testnet_usb.USBDetector.find",
                return_value=self.device,
            ),
            patch.object(USBVault, "require_available"),
            patch("builtins.input", return_value="CREATE"),
            patch("getpass.getpass", side_effect=["Strong-Test-Password", "Strong-Test-Password"]),
        ):
            call_command(
                "provision_tron_testnet_usb",
                device="TEST:",
                username="usb-test",
                wallet_name="USB Test Wallet",
            )

    def test_creates_verified_usb_vault_and_public_wallet_only(self):
        self.run_command()
        wallet = Wallet.objects.get(user=self.user, name="USB Test Wallet")
        address = WalletAddress.objects.get(wallet=wallet)
        self.assertEqual(wallet.network, self.network)
        self.assertEqual(wallet.address, address.address)
        self.assertTrue(wallet.address.startswith("T"))
        self.assertFalse(WalletVault.objects.filter(wallet=wallet).exists())
        vault = USBVault(self.device)
        self.assertTrue(vault.exists())
        recovered = vault.unlock("Strong-Test-Password")
        self.assertTrue(recovered.mnemonic)

    def test_refuses_to_overwrite_existing_vault(self):
        self.run_command()
        with (
            patch(
                "apps.usb_manager.management.commands.provision_tron_testnet_usb.USBDetector.find",
                return_value=self.device,
            ),
            self.assertRaisesMessage(CommandError, "nothing was overwritten"),
        ):
            call_command(
                "provision_tron_testnet_usb",
                device="TEST:",
                username="usb-test",
                wallet_name="Another Wallet",
            )

    def test_cancelled_confirmation_creates_nothing(self):
        with (
            patch(
                "apps.usb_manager.management.commands.provision_tron_testnet_usb.USBDetector.find",
                return_value=self.device,
            ),
            patch("builtins.input", return_value="NO"),
            self.assertRaisesMessage(CommandError, "Cancelled"),
        ):
            call_command(
                "provision_tron_testnet_usb",
                device="TEST:",
                username="usb-test",
                wallet_name="Cancelled Wallet",
            )
        self.assertFalse(Wallet.objects.filter(name="Cancelled Wallet").exists())
        self.assertFalse(USBVault(self.device).exists())
