from __future__ import annotations

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.blockchain.models import BlockchainNetwork
from apps.security.vault import VaultService

from .models import Wallet, WalletAddress, WalletVault
from .services.creation import (
    WalletCreationError,
    WalletCreationService,
)
from .services.derivation import DerivationService
from .services.hd_wallet import HDWallet
from .services.wallet_balance import (
    WalletDashboardBalanceService,
)


User = get_user_model()


# ============================================================================
# HD WALLET
# ============================================================================


class HDWalletServiceTests(TestCase):
    """Tests for BIP-39/BIP-44 wallet generation."""

    def test_generate_24_word_mnemonic(self):
        mnemonic = HDWallet.generate_mnemonic(words=24)

        self.assertEqual(
            len(mnemonic.split()),
            24,
        )

        self.assertTrue(
            HDWallet.validate_mnemonic(mnemonic)
        )

    def test_generated_mnemonic_can_create_seed(self):
        mnemonic = HDWallet.generate_mnemonic(words=12)

        seed = HDWallet.mnemonic_to_seed(
            mnemonic
        )

        self.assertIsInstance(
            seed,
            bytes,
        )

        self.assertTrue(seed)

    def test_ethereum_address_derivation(self):
        mnemonic = HDWallet.generate_mnemonic(words=12)

        seed = HDWallet.mnemonic_to_seed(
            mnemonic
        )

        result = HDWallet.derive_account(
            seed,
            coin="ethereum",
        )

        self.assertTrue(
            result.address.startswith("0x")
        )

        self.assertEqual(
            result.derivation_path,
            "m/44'/60'/0'/0/0",
        )

    def test_invalid_mnemonic_is_rejected(self):
        self.assertFalse(
            HDWallet.validate_mnemonic(
                "this is not a valid recovery phrase"
            )
        )


# ============================================================================
# DERIVATION SERVICE
# ============================================================================


class DerivationServiceTests(TestCase):
    """Tests for public address derivation."""

    def test_ethereum_mainnet_alias(self):
        mnemonic = HDWallet.generate_mnemonic(words=12)

        result = DerivationService().derive(
            mnemonic=mnemonic,
            network="ethereum-mainnet",
        )

        self.assertTrue(
            result.address.startswith("0x")
        )

        self.assertEqual(
            result.derivation_path,
            "m/44'/60'/0'/0/0",
        )

    def test_ethereum_aliases(self):
        mnemonic = HDWallet.generate_mnemonic(words=12)

        service = DerivationService()

        eth = service.derive(
            mnemonic=mnemonic,
            network="eth",
        )

        ethereum = service.derive(
            mnemonic=mnemonic,
            network="ethereum",
        )

        mainnet = service.derive(
            mnemonic=mnemonic,
            network="ethereum-mainnet",
        )

        self.assertEqual(
            eth.address,
            ethereum.address,
        )

        self.assertEqual(
            ethereum.address,
            mainnet.address,
        )

    def test_invalid_network_is_rejected(self):
        mnemonic = HDWallet.generate_mnemonic(words=12)

        with self.assertRaises(ValueError):
            DerivationService().derive(
                mnemonic=mnemonic,
                network="unsupported-network",
            )


# ============================================================================
# WALLET CREATION SERVICE
# ============================================================================


class WalletCreationServiceTests(TestCase):
    """Tests for complete persistent wallet creation."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="wallet-test-user",
            email="wallet-test@example.com",
            password="StrongTestPassword123!",
        )

        self.network = BlockchainNetwork.objects.create(
            name="Ethereum Mainnet",
            slug="ethereum-mainnet",
            symbol="ETH",
            chain_id=1,
            is_testnet=False,
            is_active=True,
        )

        self.service = WalletCreationService()

    def test_create_wallet(self):
        wallet = self.service.create_wallet(
            user=self.user,
            network=self.network,
            password="WalletPassword123!",
            words=12,
        )

        self.assertIsInstance(
            wallet,
            Wallet,
        )

        self.assertEqual(
            wallet.user,
            self.user,
        )

        self.assertEqual(
            wallet.network,
            self.network,
        )

        self.assertEqual(
            wallet.status,
            Wallet.Status.LOCKED,
        )

        self.assertTrue(
            wallet.address.startswith("0x")
        )

    def test_wallet_address_is_created(self):
        wallet = self.service.create_wallet(
            user=self.user,
            network=self.network,
            password="WalletPassword123!",
            words=12,
        )

        address = WalletAddress.objects.get(
            wallet=wallet,
            network=self.network,
        )

        self.assertEqual(
            address.address,
            wallet.address,
        )

        self.assertTrue(
            address.is_active
        )

        self.assertEqual(
            address.derivation_path,
            "m/44'/60'/0'/0/0",
        )

    def test_encrypted_vault_is_created(self):
        wallet = self.service.create_wallet(
            user=self.user,
            network=self.network,
            password="WalletPassword123!",
            words=12,
        )

        vault = WalletVault.objects.get(
            wallet=wallet,
        )

        self.assertTrue(
            vault.encrypted_payload
        )

        self.assertEqual(
            vault.version,
            VaultService.VERSION,
        )

    def test_mnemonic_is_not_stored_as_plaintext(self):
        wallet = self.service.create_wallet(
            user=self.user,
            network=self.network,
            password="WalletPassword123!",
            words=12,
        )

        vault = WalletVault.objects.get(
            wallet=wallet,
        )

        payload = bytes(
            vault.encrypted_payload
        )

        self.assertNotIn(
            b"mnemonic",
            payload,
        )

    def test_wallet_remains_locked(self):
        wallet = self.service.create_wallet(
            user=self.user,
            network=self.network,
            password="WalletPassword123!",
            words=12,
        )

        self.assertEqual(
            wallet.status,
            Wallet.Status.LOCKED,
        )

    def test_duplicate_main_wallet_is_rejected(self):
        self.service.create_wallet(
            user=self.user,
            network=self.network,
            password="WalletPassword123!",
            words=12,
        )

        with self.assertRaises(
            WalletCreationError
        ):
            self.service.create_wallet(
                user=self.user,
                network=self.network,
                password="WalletPassword123!",
                words=12,
            )

        self.assertEqual(
            Wallet.objects.filter(
                user=self.user,
                name="Main Wallet",
            ).count(),
            1,
        )

    def test_empty_password_is_rejected(self):
        with self.assertRaises(
            WalletCreationError
        ):
            self.service.create_wallet(
                user=self.user,
                network=self.network,
                password="",
            )

        self.assertEqual(
            Wallet.objects.count(),
            0,
        )

    def test_testnet_wallet_is_rejected(self):
        testnet = BlockchainNetwork.objects.create(
            name="Ethereum Testnet",
            slug="ethereum-testnet",
            symbol="ETH",
            chain_id=11155111,
            is_testnet=True,
            is_active=True,
        )

        with self.assertRaises(
            WalletCreationError
        ):
            self.service.create_wallet(
                user=self.user,
                network=testnet,
                password="WalletPassword123!",
                words=12,
            )

        self.assertEqual(
            Wallet.objects.count(),
            0,
        )

    def test_inactive_network_is_rejected(self):
        self.network.is_active = False

        self.network.save(
            update_fields=["is_active"]
        )

        with self.assertRaises(
            WalletCreationError
        ):
            self.service.create_wallet(
                user=self.user,
                network=self.network,
                password="WalletPassword123!",
                words=12,
            )

        self.assertEqual(
            Wallet.objects.count(),
            0,
        )


# ============================================================================
# DASHBOARD BALANCE ADDRESS SOURCE
# ============================================================================


class WalletDashboardBalanceAddressTests(TestCase):
    """
    Tests that dashboard balance resolution uses WalletAddress as the
    authoritative public address source.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="balance-address-test-user",
            email="balance-address-test@example.com",
            password="StrongTestPassword123!",
        )

        self.network = BlockchainNetwork.objects.create(
            name="Ethereum Mainnet",
            slug="ethereum-mainnet",
            symbol="ETH",
            chain_id=1,
            is_testnet=False,
            is_active=True,
        )

        self.wallet = Wallet.objects.create(
            user=self.user,
            network=self.network,
            name="Main Wallet",
            address="0xOLD_COMPATIBILITY_ADDRESS",
        )

        WalletAddress.objects.create(
            wallet=self.wallet,
            network=self.network,
            address="0xAUTHORITATIVE_ADDRESS",
            is_active=True,
        )

    def test_active_wallet_address_is_authoritative_for_balance_lookup(self):
        """
        The balance service must use the active WalletAddress address
        rather than the Wallet.address compatibility mirror.
        """

        captured = {}

        class FakeBalanceService:
            def __init__(
                self,
                *,
                network,
            ):
                self.network = network

            def get_wallet_balance(
                self,
                *,
                address,
                assets,
            ):
                captured["address"] = address
                captured["assets"] = assets

                from .services.balance import (
                    NativeBalance,
                    WalletBalance,
                )

                return WalletBalance(
                    address=address,
                    native=NativeBalance(
                        symbol="ETH",
                        balance=Decimal("0"),
                    ),
                    tokens=(),
                    total_asset_count=0,
                )

        service = WalletDashboardBalanceService(
            balance_service_class=FakeBalanceService,
        )

        result = service.get(
            wallet=self.wallet,
        )

        self.assertEqual(
            captured["address"],
            "0xAUTHORITATIVE_ADDRESS",
        )

        self.assertNotEqual(
            captured["address"],
            self.wallet.address,
        )

        self.assertEqual(
            result.address,
            "0xAUTHORITATIVE_ADDRESS",
        )
