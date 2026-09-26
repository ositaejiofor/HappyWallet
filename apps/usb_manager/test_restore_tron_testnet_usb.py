"""Safety tests for restoring a TRON Shasta USB vault."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.blockchain.models import BlockchainNetwork
from apps.usb_manager.detector import USBDevice
from apps.usb_manager.management.commands.provision_tron_testnet_usb import (
    derive_tron_address,
)
from apps.usb_manager.vault import USBVault
from apps.wallet.models import Wallet


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
PASSWORD = "correct horse battery staple"


class RestoreTronTestnetUSBTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="EAGLE-TECH",
            email="owner@example.com",
            password="not-used-for-usb-vault",
        )
        self.network = BlockchainNetwork.objects.create(
            name="TRON Shasta Testnet",
            slug="tron-shasta-testnet",
            symbol="TRX",
            is_testnet=True,
            is_active=True,
        )
        self.address = derive_tron_address(MNEMONIC)
        self.wallet = Wallet.objects.create(
            user=self.user,
            name="TRON USB Shasta Wallet",
            address=self.address,
            network=self.network,
            status=Wallet.Status.ACTIVE,
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.device = USBDevice(
            device_id="E:",
            mount_path=Path(self.temp.name),
            filesystem="FAT32",
        )

    def run_restore(self, *, phrase=MNEMONIC, passwords=(PASSWORD, PASSWORD)):
        output = io.StringIO()
        with (
            patch(
                "apps.usb_manager.management.commands.restore_tron_testnet_usb.USBDetector.find",
                return_value=self.device,
            ),
            patch(
                "apps.usb_manager.vault.USBVault.require_available",
                return_value=None,
            ),
            patch("builtins.input", return_value="RESTORE"),
            patch(
                "apps.usb_manager.management.commands.restore_tron_testnet_usb.getpass.getpass",
                side_effect=[phrase, *passwords],
            ),
        ):
            call_command(
                "restore_tron_testnet_usb",
                device="E:",
                username=self.user.username,
                wallet_id=str(self.wallet.pk),
                stdout=output,
            )
        return output.getvalue()

    def test_restores_matching_phrase_and_verifies_vault(self):
        output = self.run_restore()
        vault = USBVault(self.device)
        with patch.object(vault, "require_available", return_value=None):
            recovered = vault.unlock(PASSWORD)
        self.assertEqual(derive_tron_address(recovered.mnemonic or ""), self.address)
        self.assertNotIn(MNEMONIC, output)
        self.assertIn("restored and verified", output)

    def test_rejects_phrase_for_different_address_without_writing(self):
        with (
            patch(
                "apps.usb_manager.management.commands.restore_tron_testnet_usb.derive_tron_address",
                return_value="TTc5Pm65mNyqwan1kACPLFDLJNFjPFQmwZ",
            ),
            self.assertRaisesMessage(CommandError, "does not control"),
        ):
            self.run_restore()
        self.assertFalse(USBVault(self.device)._has_existing_data())

    def test_rejects_existing_or_partial_vault_without_prompting(self):
        vault = USBVault(self.device)
        vault.root.mkdir(parents=True)
        vault.metadata_path.write_text("{}", encoding="utf-8")
        with (
            patch(
                "apps.usb_manager.management.commands.restore_tron_testnet_usb.USBDetector.find",
                return_value=self.device,
            ),
            patch(
                "apps.usb_manager.management.commands.restore_tron_testnet_usb.getpass.getpass"
            ) as secret_prompt,
            self.assertRaisesMessage(CommandError, "nothing was overwritten"),
        ):
            call_command(
                "restore_tron_testnet_usb",
                device="E:",
                username=self.user.username,
                wallet_id=str(self.wallet.pk),
            )
        secret_prompt.assert_not_called()

    def test_rejects_non_testnet_wallet(self):
        self.network.is_testnet = False
        self.network.save(update_fields=["is_testnet"])
        with (
            patch(
                "apps.usb_manager.management.commands.restore_tron_testnet_usb.USBDetector.find",
                return_value=self.device,
            ),
            self.assertRaisesMessage(CommandError, "Only an existing TRON Shasta"),
        ):
            call_command(
                "restore_tron_testnet_usb",
                device="E:",
                username=self.user.username,
                wallet_id=str(self.wallet.pk),
            )
