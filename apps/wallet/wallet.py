"""
HappyWallet Wallet Service.

Responsible for wallet-level operations only.

Responsibilities
----------------
- Retrieve a user's main wallet.
- Create a user's main wallet.
- Resolve supported blockchain networks.
- Delegate address operations to WalletAddressService.

Security
--------
This service never stores or logs:
- mnemonics
- seeds
- private keys
- decrypted vault contents
"""

from __future__ import annotations

from django.db import transaction

from apps.blockchain.models import BlockchainNetwork
from apps.wallet.models import Wallet, WalletAddress

from .address import WalletAddressService


class WalletService:
    """
    Application service for wallet-level operations.

    Address derivation and address persistence are delegated to
    WalletAddressService.
    """

    MAIN_WALLET_NAME = "Main Wallet"

    def __init__(
        self,
        *,
        address_service: WalletAddressService | None = None,
    ) -> None:
        self.address_service = (
            address_service
            or WalletAddressService()
        )

    # ==================================================================
    # GET MAIN WALLET
    # ==================================================================

    @classmethod
    def get_main_wallet(
        cls,
        user,
    ) -> Wallet | None:
        """
        Return the authenticated user's main wallet.
        """

        return (
            Wallet.objects
            .select_related("network")
            .filter(
                user=user,
                name=cls.MAIN_WALLET_NAME,
            )
            .first()
        )

    # ==================================================================
    # GET OR CREATE MAIN WALLET
    # ==================================================================

    @classmethod
    @transaction.atomic
    def get_or_create_main_wallet(
        cls,
        user,
        network: BlockchainNetwork | None = None,
    ) -> tuple[Wallet, bool]:
        """
        Get or create the user's main wallet.

        New wallets always start locked.
        """

        wallet = (
            Wallet.objects
            .select_for_update()
            .filter(
                user=user,
                name=cls.MAIN_WALLET_NAME,
            )
            .first()
        )

        if wallet is not None:
            return wallet, False

        wallet = Wallet.objects.create(
            user=user,
            name=cls.MAIN_WALLET_NAME,
            network=network,
            status=Wallet.Status.LOCKED,
        )

        return wallet, True

    # ==================================================================
    # NETWORK
    # ==================================================================

    @staticmethod
    def get_network(
        slug: str,
    ) -> BlockchainNetwork:
        """
        Return an active production/mainnet blockchain network.
        """

        if not isinstance(slug, str):
            raise ValueError(
                "Network slug must be a string."
            )

        slug = slug.strip().lower()

        if not slug:
            raise ValueError(
                "Network slug is required."
            )

        return BlockchainNetwork.objects.get(
            slug=slug,
            is_active=True,
            is_testnet=False,
        )

    # ==================================================================
    # CREATE ADDRESS
    # ==================================================================

    def create_address(
        self,
        *,
        wallet: Wallet,
        mnemonic: str,
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        passphrase: str = "",
    ) -> WalletAddress:
        """
        Derive and persist a wallet address.

        Address derivation is delegated to WalletAddressService.
        """

        return self.address_service.derive_address(
            wallet=wallet,
            mnemonic=mnemonic,
            account=account,
            change=change,
            address_index=address_index,
            passphrase=passphrase,
        )

    # ==================================================================
    # GET ACTIVE ADDRESS
    # ==================================================================

    def get_active_address(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork | None = None,
    ) -> WalletAddress | None:
        """
        Return the active public address.
        """

        return self.address_service.get_address(
            wallet=wallet,
            network=network,
        )