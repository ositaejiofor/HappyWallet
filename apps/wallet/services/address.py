"""
HappyWallet Wallet Address Service.

Application boundary for managing public blockchain addresses.

Responsibilities
----------------
- Derive public wallet addresses.
- Persist public wallet addresses.
- Retrieve active addresses.
- Create or update address records.
- Deactivate addresses without deleting history.
- Maintain Wallet.address as a compatibility mirror.

Address authority
-----------------
WalletAddress is the authoritative public-address record.

Wallet.address is retained only as a compatibility field for the
wallet's primary network and must never be treated as the authoritative
source when a WalletAddress record exists.

Security boundary
-----------------
This service may temporarily receive a mnemonic and BIP-39 passphrase
only when deriving a public address.

This service MUST NEVER:

- persist a mnemonic
- persist a seed
- persist a private key
- return a mnemonic
- return a seed
- return a private key
- decrypt wallet secrets
- sign transactions
- broadcast transactions
- persist signing material

Only public address information is persisted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db import transaction

from apps.wallet.models import Wallet, WalletAddress

from .derivation import DerivationService

if TYPE_CHECKING:
    from apps.blockchain.models import BlockchainNetwork


class WalletAddressService:
    """
    Coordinate public wallet-address lifecycle operations.

    The service deliberately separates:

        derivation
            from
        persistence
            from
        address lookup.

    WalletAddress remains the authoritative public-address source.
    """

    # ========================================================================
    # INITIALIZATION
    # ========================================================================

    def __init__(
        self,
        *,
        derivation_service: DerivationService | None = None,
    ) -> None:
        """
        Initialize the address service.

        Dependency injection is preserved so tests and callers can replace
        the derivation implementation without changing this service.
        """

        self.derivation = (
            derivation_service
            if derivation_service is not None
            else DerivationService()
        )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    @staticmethod
    def _validate_wallet(
        wallet: Wallet | None,
    ) -> Wallet:
        """
        Validate and return a Wallet instance.
        """

        if wallet is None:
            raise ValueError(
                "A wallet is required."
            )

        if not isinstance(
            wallet,
            Wallet,
        ):
            raise ValueError(
                "A valid Wallet instance is required."
            )

        return wallet

    @staticmethod
    def _validate_network(
        network: BlockchainNetwork | None,
    ) -> BlockchainNetwork:
        """
        Validate and return a blockchain network.
        """

        if network is None:
            raise ValueError(
                "A blockchain network is required."
            )

        return network

    @staticmethod
    def _validate_mnemonic(
        mnemonic: str,
    ) -> str:
        """
        Validate mnemonic input without persisting it.
        """

        if not isinstance(
            mnemonic,
            str,
        ):
            raise ValueError(
                "Mnemonic must be a string."
            )

        normalized = mnemonic.strip()

        if not normalized:
            raise ValueError(
                "A mnemonic is required for address derivation."
            )

        return normalized

    @staticmethod
    def _normalize_address(
        address: str,
    ) -> str:
        """
        Normalize a public blockchain address.
        """

        if not isinstance(
            address,
            str,
        ):
            raise ValueError(
                "Wallet address must be a string."
            )

        normalized = address.strip()

        if not normalized:
            raise ValueError(
                "Wallet address cannot be empty."
            )

        return normalized

    @staticmethod
    def _normalize_derivation_path(
        derivation_path: str | None,
    ) -> str:
        """
        Normalize an optional public derivation path.
        """

        if derivation_path is None:
            return ""

        if not isinstance(
            derivation_path,
            str,
        ):
            raise ValueError(
                "Derivation path must be a string."
            )

        return derivation_path.strip()

    # ========================================================================
    # DERIVE AND STORE
    # ========================================================================

    @transaction.atomic
    def derive_address(
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
        Derive a public address and persist it.

        The mnemonic and passphrase are transient inputs only.

        No secret material is persisted.
        """

        wallet = self._validate_wallet(
            wallet,
        )

        network = self._validate_network(
            wallet.network,
        )

        mnemonic = self._validate_mnemonic(
            mnemonic,
        )

        address_info = self.derivation.derive(
            mnemonic=mnemonic,
            account=account,
            change=change,
            address_index=address_index,
            passphrase=passphrase,
            network=network.name,
        )

        if not address_info:
            raise ValueError(
                "Address derivation failed."
            )

        address = self._normalize_address(
            getattr(
                address_info,
                "address",
                "",
            ),
        )

        derivation_path = (
            self._normalize_derivation_path(
                getattr(
                    address_info,
                    "derivation_path",
                    "",
                ),
            )
        )

        return self._save_address(
            wallet=wallet,
            network=network,
            address=address,
            derivation_path=derivation_path,
        )

    # ========================================================================
    # ACTIVE ADDRESS LOOKUP
    # ========================================================================

    def get_address(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork | None = None,
    ) -> WalletAddress | None:
        """
        Return the active authoritative WalletAddress.

        If no network is supplied, the wallet's primary network is used.

        IMPORTANT:
        This method never falls back to Wallet.address. That fallback
        belongs exclusively to get_address_string(), where compatibility
        behavior is required.
        """

        if wallet is None:
            return None

        wallet = self._validate_wallet(
            wallet,
        )

        resolved_network = (
            network
            if network is not None
            else wallet.network
        )

        if resolved_network is None:
            return None

        return (
            WalletAddress.objects
            .filter(
                wallet=wallet,
                network=resolved_network,
                is_active=True,
            )
            .select_related(
                "wallet",
                "network",
            )
            .first()
        )

    # ========================================================================
    # ADDRESS STRING
    # ========================================================================

    def get_address_string(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork | None = None,
    ) -> str:
        """
        Return the active public wallet address.

        Address resolution order:

            1. active WalletAddress
            2. Wallet.address compatibility mirror

        The compatibility mirror is used only when:

            - no active WalletAddress exists, and
            - the requested network is the wallet's primary network.

        WalletAddress therefore remains authoritative whenever present.
        """

        if wallet is None:
            return ""

        wallet = self._validate_wallet(
            wallet,
        )

        address_record = self.get_address(
            wallet=wallet,
            network=network,
        )

        if address_record is not None:
            return (
                address_record.address or ""
            ).strip()

        return self._get_compatibility_address(
            wallet=wallet,
            network=network,
        )

    @staticmethod
    def _get_compatibility_address(
        *,
        wallet: Wallet,
        network: BlockchainNetwork | None,
    ) -> str:
        """
        Resolve the legacy Wallet.address compatibility mirror.

        This method intentionally does not query WalletAddress.
        """

        wallet_address = (
            wallet.address or ""
        ).strip()

        if not wallet_address:
            return ""

        if network is None:
            return wallet_address

        if wallet.network_id == network.id:
            return wallet_address

        return ""

    # ========================================================================
    # ALL ACTIVE ADDRESSES
    # ========================================================================

    def get_all_addresses(
        self,
        *,
        wallet: Wallet,
    ):
        """
        Return all active WalletAddress records for a wallet.

        The returned QuerySet remains lazy.
        """

        if wallet is None:
            return WalletAddress.objects.none()

        wallet = self._validate_wallet(
            wallet,
        )

        return (
            WalletAddress.objects
            .filter(
                wallet=wallet,
                is_active=True,
            )
            .select_related(
                "network",
            )
            .order_by(
                "network__name",
                "created_at",
            )
        )

    # ========================================================================
    # GET OR CREATE
    # ========================================================================

    @transaction.atomic
    def get_or_create_address(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        address: str | None = None,
        derivation_path: str = "",
    ) -> WalletAddress | None:
        """
        Return the existing active address.

        If no active address exists:

            - return None when no address was supplied
            - persist the supplied already-derived public address otherwise

        This method NEVER derives an address.
        """

        wallet = self._validate_wallet(
            wallet,
        )

        network = self._validate_network(
            network,
        )

        existing = self.get_address(
            wallet=wallet,
            network=network,
        )

        if existing is not None:
            return existing

        if address is None:
            return None

        wallet_address, _created = (
            self.create_address(
                wallet=wallet,
                network=network,
                address=address,
                derivation_path=derivation_path,
            )
        )

        return wallet_address

    # ========================================================================
    # CREATE / UPDATE
    # ========================================================================

    @transaction.atomic
    def create_address(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        address: str,
        derivation_path: str = "",
    ) -> tuple[WalletAddress, bool]:
        """
        Create or update a public WalletAddress.

        No mnemonic, seed, private key, or signing material is accepted.
        """

        wallet = self._validate_wallet(
            wallet,
        )

        network = self._validate_network(
            network,
        )

        normalized_address = self._normalize_address(
            address,
        )

        normalized_path = (
            self._normalize_derivation_path(
                derivation_path,
            )
        )

        return self._save_address(
            wallet=wallet,
            network=network,
            address=normalized_address,
            derivation_path=normalized_path,
        )

    # ========================================================================
    # INTERNAL PERSISTENCE
    # ========================================================================

    @staticmethod
    def _save_address(
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        address: str,
        derivation_path: str = "",
    ) -> tuple[WalletAddress, bool]:
        """
        Persist public address information.

        WalletAddress is the authoritative record.

        Wallet.address is synchronized only when the address belongs to
        the wallet's primary network.
        """

        wallet_address, created = (
            WalletAddress.objects.update_or_create(
                wallet=wallet,
                network=network,
                defaults={
                    "address": address,
                    "derivation_path": derivation_path,
                    "is_active": True,
                },
            )
        )

        WalletAddressService._sync_compatibility_mirror(
            wallet=wallet,
            network=network,
            address=address,
        )

        return wallet_address, created

    @staticmethod
    def _sync_compatibility_mirror(
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        address: str,
    ) -> None:
        """
        Synchronize Wallet.address for the wallet's primary network.

        This field is a compatibility mirror only.
        """

        if wallet.network_id != network.id:
            return

        if wallet.address == address:
            return

        wallet.address = address

        wallet.save(
            update_fields=[
                "address",
                "updated_at",
            ],
        )

    # ========================================================================
    # DEACTIVATION
    # ========================================================================

    @transaction.atomic
    def deactivate_address(
        self,
        *,
        wallet_address: WalletAddress | None,
    ) -> bool:
        """
        Deactivate an address without deleting historical data.

        When the deactivated address is also the wallet's primary
        compatibility mirror, Wallet.address is cleared.
        """

        if wallet_address is None:
            return False

        if not isinstance(
            wallet_address,
            WalletAddress,
        ):
            raise ValueError(
                "A valid WalletAddress is required."
            )

        if not wallet_address.is_active:
            return True

        wallet_address.is_active = False

        wallet_address.save(
            update_fields=[
                "is_active",
                "updated_at",
            ],
        )

        self._clear_compatibility_mirror_if_matching(
            wallet_address=wallet_address,
        )

        return True

    @staticmethod
    def _clear_compatibility_mirror_if_matching(
        *,
        wallet_address: WalletAddress,
    ) -> None:
        """
        Clear Wallet.address when it mirrors the deactivated
        primary-network WalletAddress.
        """

        wallet = wallet_address.wallet

        if wallet is None:
            return

        if wallet.network_id != wallet_address.network_id:
            return

        if wallet.address != wallet_address.address:
            return

        wallet.address = ""

        wallet.save(
            update_fields=[
                "address",
                "updated_at",
            ],
        )


# ============================================================================
# DEFAULT SERVICE
# ============================================================================


wallet_address_service = WalletAddressService()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


def get_wallet_address(
    wallet: Wallet,
    network: BlockchainNetwork | None = None,
) -> WalletAddress | None:
    """
    Return the active authoritative WalletAddress.
    """

    return wallet_address_service.get_address(
        wallet=wallet,
        network=network,
    )


def get_wallet_address_string(
    wallet: Wallet,
    network: BlockchainNetwork | None = None,
) -> str:
    """
    Return the active public wallet address string.
    """

    return wallet_address_service.get_address_string(
        wallet=wallet,
        network=network,
    )


def get_active_wallet_addresses(
    wallet: Wallet,
):
    """
    Return all active public addresses belonging to a wallet.
    """

    return wallet_address_service.get_all_addresses(
        wallet=wallet,
    )


def create_wallet_address(
    wallet: Wallet,
    network: BlockchainNetwork,
    address: str,
    derivation_path: str = "",
) -> tuple[WalletAddress, bool]:
    """
    Create or update a public wallet address.
    """

    return wallet_address_service.create_address(
        wallet=wallet,
        network=network,
        address=address,
        derivation_path=derivation_path,
    )


def get_or_create_wallet_address(
    wallet: Wallet,
    network: BlockchainNetwork,
    address: str | None = None,
    derivation_path: str = "",
) -> WalletAddress | None:
    """
    Return an existing active address or persist an already-derived one.
    """

    return wallet_address_service.get_or_create_address(
        wallet=wallet,
        network=network,
        address=address,
        derivation_path=derivation_path,
    )


def deactivate_wallet_address(
    wallet_address: WalletAddress,
) -> bool:
    """
    Deactivate a public wallet address without deleting it.
    """

    return wallet_address_service.deactivate_address(
        wallet_address=wallet_address,
    )


def derive_and_store_wallet_address(
    wallet: Wallet,
    mnemonic: str,
    account: int = 0,
    change: int = 0,
    address_index: int = 0,
    passphrase: str = "",
) -> WalletAddress:
    """
    Derive a public address and persist only public information.

    The mnemonic and passphrase are transient and are never persisted.
    """

    return wallet_address_service.derive_address(
        wallet=wallet,
        mnemonic=mnemonic,
        account=account,
        change=change,
        address_index=address_index,
        passphrase=passphrase,
    )
