"""
HappyWallet Wallet Creation Service.

Application boundary for creating a complete encrypted wallet.

Creation flow
-------------

    1. Validate creation inputs.
    2. Validate blockchain network safety.
    3. Prevent duplicate Main Wallet creation.
    4. Generate BIP-39 mnemonic.
    5. Create the Wallet database record.
    6. Derive the BIP-39 seed in memory.
    7. Derive the public blockchain address.
    8. Persist the public WalletAddress.
    9. Encrypt the mnemonic into a WalletVault.
   10. Persist the encrypted WalletVault.
   11. Return the wallet LOCKED.

Security boundary
-----------------

This service may temporarily handle:

    - BIP-39 mnemonic
    - BIP-39 passphrase
    - derived seed

This service MUST NEVER:

    - persist a plaintext mnemonic
    - persist a seed
    - persist a private key
    - return a mnemonic
    - return a seed
    - return a private key
    - sign transactions
    - broadcast transactions
    - expose decrypted vault material

The mnemonic is passed only to the derivation and encryption layers.

The seed is created only for address derivation and is never persisted.

Network safety
--------------

Wallet creation is permitted only for:

    - active networks
    - mainnet networks

Testnets and inactive networks are rejected before mnemonic generation
and before any Wallet record is created.

Persistence
-----------

WalletAddress is the authoritative public address record.

Wallet.address is maintained by WalletAddressService as the compatibility
mirror for the wallet's primary network.

WalletVault contains encrypted secret material only.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from apps.blockchain.models import BlockchainNetwork
from apps.security.vault import VaultService, WalletSecret
from apps.wallet.models import Wallet, WalletVault

from .address import WalletAddressService
from .hd_wallet import HDWalletService
from .wallet import WalletService


class WalletCreationError(Exception):
    """Raised when wallet creation fails."""


class WalletCreationService:
    """
    Orchestrate complete encrypted wallet creation.

    This service is intentionally an application-level coordinator.
    Cryptographic operations, address management, and vault encryption
    remain delegated to their dedicated services.
    """

    def __init__(
        self,
        *,
        hd_wallet_service: type[HDWalletService] = HDWalletService,
        wallet_service: type[WalletService] = WalletService,
        address_service: WalletAddressService | None = None,
        vault_service: VaultService | None = None,
    ) -> None:
        """
        Initialize the wallet creation coordinator.

        Dependency injection is preserved so tests and callers can replace
        individual services without changing the creation workflow.
        """

        self.hd_wallet = hd_wallet_service
        self.wallet_service = wallet_service

        self.address_service = (
            address_service
            if address_service is not None
            else WalletAddressService()
        )

        self.vault = (
            vault_service
            if vault_service is not None
            else VaultService()
        )

    # ======================================================================
    # PUBLIC API
    # ======================================================================

    @transaction.atomic
    def create_wallet(
        self,
        *,
        user,
        network: BlockchainNetwork,
        password: str,
        words: int = 24,
        passphrase: str = "",
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
    ) -> Wallet:
        """
        Create and persist a complete encrypted wallet.

        The returned Wallet is always LOCKED.

        Sensitive material is never returned and is never persisted
        in plaintext.
        """

        self._validate_inputs(
            user=user,
            network=network,
            password=password,
            passphrase=passphrase,
        )

        self._validate_network(
            network,
        )

        self._ensure_main_wallet_does_not_exist(
            user,
        )

        mnemonic = None
        seed = None

        try:
            # --------------------------------------------------------------
            # 1. Generate BIP-39 mnemonic.
            # --------------------------------------------------------------
            mnemonic = self._generate_mnemonic(
                words=words,
            )

            # --------------------------------------------------------------
            # 2. Create the persistent wallet record.
            #
            # The record is created LOCKED and contains no secret material.
            # --------------------------------------------------------------
            wallet = self._create_wallet_record(
                user=user,
                network=network,
            )

            # --------------------------------------------------------------
            # 3. Derive BIP-39 seed in memory.
            # --------------------------------------------------------------
            seed = self._create_seed(
                mnemonic=mnemonic,
                passphrase=passphrase,
            )

            # --------------------------------------------------------------
            # 4. Derive public blockchain address.
            # --------------------------------------------------------------
            address_info = self._derive_public_address(
                seed=seed,
                network=network,
                account=account,
                change=change,
                address_index=address_index,
            )

            # --------------------------------------------------------------
            # 5. Persist public address information only.
            # --------------------------------------------------------------
            self._persist_public_address(
                wallet=wallet,
                network=network,
                address_info=address_info,
            )

            # --------------------------------------------------------------
            # 6. Encrypt the mnemonic.
            # --------------------------------------------------------------
            encrypted_payload = self._encrypt_mnemonic(
                mnemonic=mnemonic,
                password=password,
            )

            # --------------------------------------------------------------
            # 7. Persist encrypted vault.
            # --------------------------------------------------------------
            self._persist_vault(
                wallet=wallet,
                encrypted_payload=encrypted_payload,
            )

            # --------------------------------------------------------------
            # 8. Return the wallet.
            #
            # The wallet remains LOCKED.
            # --------------------------------------------------------------
            return wallet

        except WalletCreationError:
            raise

        except Exception as exc:
            raise WalletCreationError(
                "Unable to create wallet."
            ) from exc

        finally:
            # Python does not guarantee memory zeroization. Dropping local
            # references reduces the lifetime of sensitive material held by
            # this service.
            mnemonic = None
            seed = None

    # ======================================================================
    # INPUT VALIDATION
    # ======================================================================

    @staticmethod
    def _validate_inputs(
        *,
        user: Any,
        network: BlockchainNetwork | None,
        password: str,
        passphrase: str,
    ) -> None:
        """
        Validate basic wallet-creation inputs.

        This method performs no database writes and generates no secrets.
        """

        if user is None:
            raise WalletCreationError(
                "A user is required."
            )

        if network is None:
            raise WalletCreationError(
                "A blockchain network is required."
            )

        if not isinstance(password, str) or not password:
            raise WalletCreationError(
                "A wallet password is required."
            )

        if not isinstance(passphrase, str):
            raise WalletCreationError(
                "BIP-39 passphrase must be a string."
            )

    # ======================================================================
    # NETWORK VALIDATION
    # ======================================================================

    @staticmethod
    def _validate_network(
        network: BlockchainNetwork,
    ) -> None:
        """
        Validate that wallet creation is allowed on the requested network.

        Only active mainnet networks are permitted.

        This check occurs before:

            - mnemonic generation
            - Wallet creation
            - seed generation
            - address derivation
        """

        if not isinstance(
            network,
            BlockchainNetwork,
        ):
            raise WalletCreationError(
                "A valid blockchain network is required."
            )

        if not network.is_active:
            raise WalletCreationError(
                "The selected blockchain network is inactive."
            )

        if network.is_testnet:
            raise WalletCreationError(
                "Wallet creation on testnet networks is not allowed."
            )

    # ======================================================================
    # DUPLICATE PROTECTION
    # ======================================================================

    def _ensure_main_wallet_does_not_exist(
        self,
        user,
    ) -> None:
        """
        Prevent creation of a second Main Wallet for the user.
        """

        existing = self.wallet_service.get_main_wallet(
            user,
        )

        if existing is not None:
            raise WalletCreationError(
                "The user already has a Main Wallet."
            )

    # ======================================================================
    # MNEMONIC GENERATION
    # ======================================================================

    def _generate_mnemonic(
        self,
        *,
        words: int,
    ) -> str:
        """
        Generate a BIP-39 mnemonic through HDWalletService.

        The mnemonic remains in memory only and is never persisted
        directly by this service.
        """

        try:
            mnemonic = self.hd_wallet.generate_mnemonic(
                words=words,
            )
        except Exception as exc:
            raise WalletCreationError(
                "Unable to generate wallet recovery material."
            ) from exc

        if not isinstance(mnemonic, str) or not mnemonic.strip():
            raise WalletCreationError(
                "Wallet mnemonic generation failed."
            )

        return mnemonic

    # ======================================================================
    # WALLET RECORD
    # ======================================================================

    def _create_wallet_record(
        self,
        *,
        user,
        network: BlockchainNetwork,
    ) -> Wallet:
        """
        Create the persistent Wallet record.

        The wallet is explicitly created LOCKED.

        No mnemonic, seed, private key, or other secret material is
        persisted in the Wallet model.
        """

        return Wallet.objects.create(
            user=user,
            name=self.wallet_service.MAIN_WALLET_NAME,
            network=network,
            status=Wallet.Status.LOCKED,
        )

    # ======================================================================
    # SEED DERIVATION
    # ======================================================================

    def _create_seed(
        self,
        *,
        mnemonic: str,
        passphrase: str,
    ):
        """
        Derive the BIP-39 seed in memory.

        The seed is used only for public address derivation and is never
        persisted or returned.
        """

        try:
            seed = self.hd_wallet.mnemonic_to_seed(
                mnemonic,
                passphrase=passphrase,
            )
        except Exception as exc:
            raise WalletCreationError(
                "Unable to derive wallet seed."
            ) from exc

        if not seed:
            raise WalletCreationError(
                "Wallet seed derivation failed."
            )

        return seed

    # ======================================================================
    # PUBLIC ADDRESS DERIVATION
    # ======================================================================

    def _derive_public_address(
        self,
        *,
        seed,
        network: BlockchainNetwork,
        account: int,
        change: int,
        address_index: int,
    ):
        """
        Derive the public blockchain address from the in-memory seed.

        Private-key material is not persisted by this service.
        """

        try:
            address_info = self.hd_wallet.derive_account(
                seed,
                coin=network.slug,
                account=account,
                change=change,
                address_index=address_index,
            )
        except Exception as exc:
            raise WalletCreationError(
                "Unable to derive wallet address."
            ) from exc

        if not address_info:
            raise WalletCreationError(
                "Wallet address derivation failed."
            )

        address = getattr(
            address_info,
            "address",
            "",
        )

        if not isinstance(address, str) or not address.strip():
            raise WalletCreationError(
                "Wallet address derivation returned an invalid address."
            )

        return address_info

    # ======================================================================
    # PUBLIC ADDRESS PERSISTENCE
    # ======================================================================

    def _persist_public_address(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        address_info,
    ) -> None:
        """
        Persist public address information through WalletAddressService.

        WalletAddressService remains responsible for:

            - WalletAddress persistence
            - authoritative address management
            - Wallet.address compatibility synchronization

        No secret material is persisted here.
        """

        address = getattr(
            address_info,
            "address",
            "",
        )

        derivation_path = getattr(
            address_info,
            "derivation_path",
            "",
        )

        try:
            self.address_service.create_address(
                wallet=wallet,
                network=network,
                address=address,
                derivation_path=derivation_path,
            )
        except Exception as exc:
            raise WalletCreationError(
                "Unable to persist wallet address."
            ) from exc

    # ======================================================================
    # MNEMONIC ENCRYPTION
    # ======================================================================

    def _encrypt_mnemonic(
        self,
        *,
        mnemonic: str,
        password: str,
    ):
        """
        Encrypt the mnemonic through VaultService.

        Only the encrypted payload leaves this method.

        The plaintext mnemonic is never persisted.
        """

        try:
            secret = WalletSecret(
                mnemonic=mnemonic,
            )

            encrypted_payload = self.vault.create_vault(
                secret,
                password,
            )

        except Exception as exc:
            raise WalletCreationError(
                "Unable to encrypt wallet recovery material."
            ) from exc

        if not encrypted_payload:
            raise WalletCreationError(
                "Wallet vault encryption failed."
            )

        return encrypted_payload

    # ======================================================================
    # VAULT PERSISTENCE
    # ======================================================================

    def _persist_vault(
        self,
        *,
        wallet: Wallet,
        encrypted_payload,
    ) -> WalletVault:
        """
        Persist the encrypted wallet vault.

        The plaintext mnemonic never reaches the database.
        """

        try:
            return WalletVault.objects.create(
                wallet=wallet,
                encrypted_payload=encrypted_payload,
                version=self.vault.VERSION,
            )
        except Exception as exc:
            raise WalletCreationError(
                "Unable to persist wallet vault."
            ) from exc
