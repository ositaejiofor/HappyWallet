"""
HappyWallet Wallet Service.

Application boundary for wallet identity, lifecycle state, and public
address access.

Responsibilities
----------------
- Resolve the user's Main Wallet.
- Create a locked Main Wallet when explicitly requested.
- Resolve active production blockchain networks.
- Delegate public address derivation and persistence.
- Resolve authoritative WalletAddress records.
- Manage wallet lifecycle state.

Security boundary
-----------------
This service MUST NEVER:

- persist a mnemonic
- persist a seed
- persist a private key
- persist a BIP-39 passphrase
- decrypt wallet secrets
- expose decrypted vault material
- sign transactions
- broadcast transactions

Mnemonic/passphrase handling is delegated to WalletAddressService and
the dedicated wallet/security layers.

Address authority
-----------------
WalletAddressService is the authoritative source for public addresses.

Wallet.address is only a compatibility mirror maintained by
WalletAddressService.
"""

from __future__ import annotations

from django.db import transaction

from apps.blockchain.models import BlockchainNetwork
from apps.wallet.models import Wallet, WalletAddress

from .address import WalletAddressService


class WalletService:
    """
    Application service for wallet identity and lifecycle operations.

    This service deliberately contains no cryptographic implementation.
    """

    MAIN_WALLET_NAME = "Main Wallet"

    # ========================================================================
    # WALLET LOOKUP
    # ========================================================================

    @classmethod
    def get_main_wallet(
        cls,
        user,
    ) -> Wallet | None:
        """
        Return the user's Main Wallet.

        The wallet's primary blockchain network is eagerly loaded.

        No wallet secrets are accessed.
        """

        if user is None:
            return None

        return (
            Wallet.objects
            .select_related("network")
            .filter(
                user=user,
                name=cls.MAIN_WALLET_NAME,
            )
            .first()
        )

    # ========================================================================
    # WALLET CREATION
    # ========================================================================

    @classmethod
    @transaction.atomic
    def get_or_create_main_wallet(
        cls,
        user,
        network: BlockchainNetwork | None = None,
    ) -> tuple[Wallet, bool]:
        """
        Return the user's Main Wallet.

        If no Main Wallet exists, create one in LOCKED state.

        This method creates only the wallet identity record. It does not:

        - generate a mnemonic
        - derive a seed
        - derive a private key
        - encrypt recovery material
        - create a WalletVault

        Complete encrypted wallet creation belongs to
        WalletCreationService.
        """

        cls._require_user(user)

        wallet = (
            Wallet.objects
            .select_for_update()
            .select_related("network")
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

    # ========================================================================
    # NETWORK
    # ========================================================================

    @staticmethod
    def get_network(
        slug: str,
    ) -> BlockchainNetwork:
        """
        Return an active production/mainnet blockchain network.

        Testnets and inactive networks are excluded.
        """

        if not isinstance(slug, str):
            raise ValueError(
                "Network slug must be a string."
            )

        normalized_slug = slug.strip().lower()

        if not normalized_slug:
            raise ValueError(
                "Network slug is required."
            )

        return BlockchainNetwork.objects.get(
            slug=normalized_slug,
            is_active=True,
            is_testnet=False,
        )

    # ========================================================================
    # PUBLIC ADDRESS CREATION
    # ========================================================================

    @classmethod
    @transaction.atomic
    def create_address(
        cls,
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        mnemonic: str,
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        passphrase: str = "",
    ) -> WalletAddress:
        """
        Derive and persist a public blockchain address.

        Sensitive mnemonic/passphrase material is delegated immediately
        to WalletAddressService and is never persisted by this service.
        """

        cls._require_wallet(wallet)
        cls._require_network(network)

        if wallet.network_id != network.id:
            raise ValueError(
                "The requested network does not match "
                "the wallet's primary network."
            )

        return WalletAddressService().derive_address(
            wallet=wallet,
            mnemonic=mnemonic,
            account=account,
            change=change,
            address_index=address_index,
            passphrase=passphrase,
        )

    # ========================================================================
    # PUBLIC ADDRESS LOOKUP
    # ========================================================================

    @classmethod
    def get_active_address(
        cls,
        *,
        wallet: Wallet,
        network: BlockchainNetwork | None = None,
    ) -> WalletAddress | None:
        """
        Return the active authoritative WalletAddress.

        WalletAddressService owns address resolution.
        """

        if wallet is None:
            return None

        cls._require_wallet(wallet)

        return WalletAddressService().get_address(
            wallet=wallet,
            network=network,
        )

    @classmethod
    def get_address_string(
        cls,
        *,
        wallet: Wallet,
        network: BlockchainNetwork | None = None,
    ) -> str:
        """
        Return the authoritative active public address.

        WalletAddressService is responsible for compatibility fallback
        behavior involving Wallet.address.
        """

        if wallet is None:
            return ""

        cls._require_wallet(wallet)

        return WalletAddressService().get_address_string(
            wallet=wallet,
            network=network,
        )

    # ========================================================================
    # ALL ACTIVE ADDRESSES
    # ========================================================================

    @classmethod
    def get_all_addresses(
        cls,
        *,
        wallet: Wallet,
    ):
        """
        Return all active public addresses belonging to the wallet.

        The returned QuerySet remains lazy.
        """

        if wallet is None:
            return WalletAddress.objects.none()

        cls._require_wallet(wallet)

        return WalletAddressService().get_all_addresses(
            wallet=wallet,
        )

    # ========================================================================
    # WALLET STATE
    # ========================================================================

    @classmethod
    @transaction.atomic
    def lock_wallet(
        cls,
        wallet: Wallet,
    ) -> Wallet:
        """
        Set wallet state to LOCKED.

        No vault or secret material is accessed.
        """

        cls._require_wallet(wallet)

        return cls._set_status(
            wallet,
            Wallet.Status.LOCKED,
        )

    @classmethod
    @transaction.atomic
    def activate_wallet(
        cls,
        wallet: Wallet,
    ) -> Wallet:
        """
        Set wallet state to ACTIVE.

        No vault or secret material is accessed.
        """

        cls._require_wallet(wallet)

        return cls._set_status(
            wallet,
            Wallet.Status.ACTIVE,
        )

    @classmethod
    @transaction.atomic
    def suspend_wallet(
        cls,
        wallet: Wallet,
    ) -> Wallet:
        """
        Set wallet state to SUSPENDED.

        No vault or secret material is accessed.
        """

        cls._require_wallet(wallet)

        return cls._set_status(
            wallet,
            Wallet.Status.SUSPENDED,
        )

    @classmethod
    @transaction.atomic
    def archive_wallet(
        cls,
        wallet: Wallet,
    ) -> Wallet:
        """
        Set wallet state to ARCHIVED.

        No vault or secret material is accessed.
        """

        cls._require_wallet(wallet)

        return cls._set_status(
            wallet,
            Wallet.Status.ARCHIVED,
        )

    # ========================================================================
    # INTERNAL VALIDATION
    # ========================================================================

    @staticmethod
    def _require_user(
        user,
    ) -> None:
        """
        Validate a user argument.

        The project intentionally accepts its configured user model
        without imposing a concrete authentication-model type here.
        """

        if user is None:
            raise ValueError(
                "A user is required."
            )

    @staticmethod
    def _require_wallet(
        wallet: Wallet,
    ) -> Wallet:
        """
        Validate and return a Wallet instance.
        """

        if wallet is None:
            raise ValueError(
                "A wallet is required."
            )

        if not isinstance(wallet, Wallet):
            raise ValueError(
                "A valid Wallet instance is required."
            )

        return wallet

    @staticmethod
    def _require_network(
        network: BlockchainNetwork | None,
    ) -> BlockchainNetwork:
        """
        Validate and return a blockchain network.
        """

        if network is None:
            raise ValueError(
                "A blockchain network is required."
            )

        if not isinstance(
            network,
            BlockchainNetwork,
        ):
            raise ValueError(
                "A valid blockchain network is required."
            )

        return network

    @staticmethod
    def _set_status(
        wallet: Wallet,
        status,
    ) -> Wallet:
        """
        Persist a wallet lifecycle-state transition.
        """

        if wallet.status == status:
            return wallet

        wallet.status = status

        wallet.save(
            update_fields=[
                "status",
                "updated_at",
            ],
        )

        return wallet