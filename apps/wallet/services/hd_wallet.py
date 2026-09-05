"""
HappyWallet HD Wallet Engine.

Implements the wallet seed layer using BIP-39/BIP-32/BIP-44
through the bip_utils library.

Security principles:

    Mnemonic
        ↓
    BIP-39 seed
        ↓
    BIP-44 derivation
        ↓
    Private key
        ↓
    Address

Security boundary
-----------------

This module MUST NOT:

    - broadcast transactions
    - connect to blockchain RPCs
    - store passwords
    - write plaintext seeds to disk
    - send private keys through USB transport
    - persist mnemonic phrases
    - persist private keys
    - log mnemonic phrases
    - log private keys

Private key material returned by derive_private_key() must remain
inside the signing environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicGenerator,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39WordsNum,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)


# ============================================================================
# EXCEPTIONS
# ============================================================================


class HDWalletError(Exception):
    """Base exception for HD wallet errors."""


class InvalidMnemonicError(HDWalletError):
    """Raised when a mnemonic is invalid."""


class InvalidPathError(HDWalletError):
    """Raised when a derivation path is invalid."""


class UnsupportedCoinError(HDWalletError):
    """Raised when a blockchain/coin is unsupported."""


# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass(frozen=True)
class DerivedAccount:
    """
    Public information about a derived HD account.

    No private key or mnemonic is included.
    """

    coin: str
    network: str
    account: int
    change: int
    address_index: int
    derivation_path: str
    address: str
    public_key: str


@dataclass(frozen=True)
class WalletSeed:
    """
    In-memory wallet seed representation.

    WARNING
    -------

    This object contains highly sensitive material.

    Never:

        - serialize it
        - print it
        - log it
        - store it in the database
        - send it over HTTP
        - send it over USB
    """

    mnemonic: str
    seed: bytes


# ============================================================================
# HD WALLET ENGINE
# ============================================================================


class HDWallet:
    """
    BIP-39/BIP-32/BIP-44 HD wallet engine.

    Currently supported:

        Bitcoin
        Ethereum

    Network aliases such as:

        ethereum
        eth
        ethereum-mainnet

    resolve to the same BIP-44 Ethereum coin type.
    """

    DEFAULT_LANGUAGE = Bip39Languages.ENGLISH

    # 24-word BIP-39 mnemonic = 256 bits of entropy.
    DEFAULT_ENTROPY_BITS = 256

    DEFAULT_ACCOUNT = 0
    DEFAULT_CHANGE = Bip44Changes.CHAIN_EXT
    DEFAULT_ADDRESS_INDEX = 0

    # ----------------------------------------------------------------------
    # COIN MAP
    # ----------------------------------------------------------------------

    COINS = {
        # Bitcoin
        "bitcoin": Bip44Coins.BITCOIN,
        "btc": Bip44Coins.BITCOIN,
        "bitcoin-mainnet": Bip44Coins.BITCOIN,
        "btc-mainnet": Bip44Coins.BITCOIN,

        # Ethereum
        "ethereum": Bip44Coins.ETHEREUM,
        "eth": Bip44Coins.ETHEREUM,
        "ethereum-mainnet": Bip44Coins.ETHEREUM,
        "eth-mainnet": Bip44Coins.ETHEREUM,
    }

    # Canonical names used in returned public information.
    CANONICAL_COINS = {
        "bitcoin": "bitcoin",
        "btc": "bitcoin",
        "bitcoin-mainnet": "bitcoin",
        "btc-mainnet": "bitcoin",

        "ethereum": "ethereum",
        "eth": "ethereum",
        "ethereum-mainnet": "ethereum",
        "eth-mainnet": "ethereum",
    }

    # ----------------------------------------------------------------------
    # MNEMONIC GENERATION
    # ----------------------------------------------------------------------

    @classmethod
    def generate_mnemonic(
        cls,
        *,
        words: int = 24,
    ) -> str:
        """
        Generate a cryptographically secure BIP-39 mnemonic.

        Supported lengths:

            12
            15
            18
            21
            24
        """

        word_map = {
            12: Bip39WordsNum.WORDS_NUM_12,
            15: Bip39WordsNum.WORDS_NUM_15,
            18: Bip39WordsNum.WORDS_NUM_18,
            21: Bip39WordsNum.WORDS_NUM_21,
            24: Bip39WordsNum.WORDS_NUM_24,
        }

        try:
            words_enum = word_map[words]
        except KeyError as exc:
            raise ValueError(
                "Mnemonic must contain "
                "12, 15, 18, 21 or 24 words."
            ) from exc

        try:
            mnemonic = Bip39MnemonicGenerator(
                cls.DEFAULT_LANGUAGE
            ).FromWordsNumber(
                words_enum
            )

            return str(mnemonic)

        except Exception as exc:
            raise HDWalletError(
                "Unable to generate BIP-39 mnemonic."
            ) from exc

    # ----------------------------------------------------------------------
    # MNEMONIC VALIDATION
    # ----------------------------------------------------------------------

    @classmethod
    def validate_mnemonic(
        cls,
        mnemonic: str,
    ) -> bool:
        """
        Validate a BIP-39 mnemonic.

        Returns False instead of raising for invalid input.
        """

        if not isinstance(mnemonic, str):
            return False

        normalized = " ".join(
            mnemonic.strip().split()
        )

        if not normalized:
            return False

        try:
            Bip39MnemonicValidator(
                cls.DEFAULT_LANGUAGE
            ).Validate(
                normalized
            )

            return True

        except Exception:
            return False

    # ----------------------------------------------------------------------
    # MNEMONIC -> SEED
    # ----------------------------------------------------------------------

    @classmethod
    def mnemonic_to_seed(
        cls,
        mnemonic: str,
        *,
        passphrase: str = "",
    ) -> bytes:
        """
        Convert a valid BIP-39 mnemonic to a seed.

        The returned bytes are sensitive and must remain in memory.
        """

        if not cls.validate_mnemonic(mnemonic):
            raise InvalidMnemonicError(
                "Invalid BIP-39 mnemonic."
            )

        if not isinstance(passphrase, str):
            raise TypeError(
                "BIP-39 passphrase must be a string."
            )

        try:
            generator = Bip39SeedGenerator(
                " ".join(mnemonic.strip().split())
            )

            return generator.Generate(
                passphrase
            )

        except Exception as exc:
            raise HDWalletError(
                "Unable to generate BIP-39 seed."
            ) from exc

    # ----------------------------------------------------------------------
    # CREATE SEED OBJECT
    # ----------------------------------------------------------------------

    @classmethod
    def create_seed(
        cls,
        mnemonic: str,
        *,
        passphrase: str = "",
    ) -> WalletSeed:
        """
        Create an in-memory WalletSeed object.
        """

        normalized_mnemonic = " ".join(
            mnemonic.strip().split()
        )

        seed = cls.mnemonic_to_seed(
            normalized_mnemonic,
            passphrase=passphrase,
        )

        return WalletSeed(
            mnemonic=normalized_mnemonic,
            seed=seed,
        )

    # ----------------------------------------------------------------------
    # COIN RESOLUTION
    # ----------------------------------------------------------------------

    @classmethod
    def normalize_coin(
        cls,
        coin: str,
    ) -> str:
        """
        Normalize a coin/network identifier to its canonical name.

        Examples:

            ethereum
            eth
            ethereum-mainnet
            eth-mainnet

        all become:

            ethereum
        """

        if not isinstance(coin, str):
            raise UnsupportedCoinError(
                "Coin must be a string."
            )

        normalized = coin.strip().lower()

        if not normalized:
            raise UnsupportedCoinError(
                "Coin cannot be empty."
            )

        try:
            return cls.CANONICAL_COINS[normalized]

        except KeyError as exc:
            raise UnsupportedCoinError(
                f"Unsupported coin: {coin}"
            ) from exc

    @classmethod
    def get_coin(
        cls,
        coin: str,
    ) -> Bip44Coins:
        """
        Resolve a coin/network identifier to a Bip44Coins value.
        """

        if not isinstance(coin, str):
            raise UnsupportedCoinError(
                "Coin must be a string."
            )

        normalized = coin.strip().lower()

        try:
            return cls.COINS[normalized]

        except KeyError as exc:
            raise UnsupportedCoinError(
                f"Unsupported coin: {coin}"
            ) from exc

    # ----------------------------------------------------------------------
    # ROOT WALLET
    # ----------------------------------------------------------------------

    @classmethod
    def root_wallet(
        cls,
        seed: bytes,
        *,
        coin: str = "ethereum",
    ) -> Any:
        """
        Create the BIP-44 root wallet from a seed.
        """

        if not isinstance(seed, bytes):
            raise TypeError(
                "Seed must be bytes."
            )

        if not seed:
            raise ValueError(
                "Seed cannot be empty."
            )

        coin_type = cls.get_coin(coin)

        try:
            return Bip44.FromSeed(
                seed,
                coin_type,
            )

        except Exception as exc:
            raise HDWalletError(
                "Unable to create HD wallet."
            ) from exc

    # ----------------------------------------------------------------------
    # DERIVATION PATH
    # ----------------------------------------------------------------------

    @staticmethod
    def _build_derivation_path(
        *,
        coin: str,
        account: int,
        change: int,
        address_index: int,
    ) -> str:
        """
        Build the standard BIP-44 derivation path.

        We deliberately construct this ourselves instead of calling
        address_node.Path(), because the installed bip_utils version
        does not expose Path() on that object.

        Bitcoin:

            m/44'/0'/account'/change/index

        Ethereum:

            m/44'/60'/account'/change/index
        """

        coin_type = {
            "bitcoin": 0,
            "ethereum": 60,
        }.get(coin)

        if coin_type is None:
            raise UnsupportedCoinError(
                f"Unsupported coin for BIP-44 path: {coin}"
            )

        return (
            f"m/44'/{coin_type}'/"
            f"{account}'/{change}/{address_index}"
        )

    # ----------------------------------------------------------------------
    # DERIVE ADDRESS ACCOUNT
    # ----------------------------------------------------------------------

    @classmethod
    def derive_account(
        cls,
        seed: bytes,
        *,
        coin: str = "ethereum",
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
    ) -> DerivedAccount:
        """
        Derive public account information.

        Standard BIP-44 structure:

            m / 44' / coin_type' / account' / change / address_index

        No private key is returned.
        """

        cls._validate_indexes(
            account=account,
            change=change,
            address_index=address_index,
        )

        normalized_coin = cls.normalize_coin(
            coin
        )

        wallet = cls.root_wallet(
            seed,
            coin=normalized_coin,
        )

        try:
            account_node = (
                wallet
                .Purpose()
                .Coin()
                .Account(account)
            )

            change_type = (
                Bip44Changes.CHAIN_EXT
                if change == 0
                else Bip44Changes.CHAIN_INT
            )

            change_node = account_node.Change(
                change_type
            )

            address_node = change_node.AddressIndex(
                address_index
            )

            path = cls._build_derivation_path(
                coin=normalized_coin,
                account=account,
                change=change,
                address_index=address_index,
            )

            public_key = (
                address_node
                .PublicKey()
                .RawCompressed()
                .ToHex()
            )

            address = (
                address_node
                .PublicKey()
                .ToAddress()
            )

            return DerivedAccount(
                coin=normalized_coin,
                network="mainnet",
                account=account,
                change=change,
                address_index=address_index,
                derivation_path=path,
                address=address,
                public_key=public_key,
            )

        except HDWalletError:
            raise

        except Exception as exc:
            raise HDWalletError(
                "Unable to derive wallet account."
            ) from exc

    # ----------------------------------------------------------------------
    # PRIVATE KEY
    # ----------------------------------------------------------------------

    @classmethod
    def derive_private_key(
        cls,
        seed: bytes,
        *,
        coin: str = "ethereum",
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
    ) -> bytes:
        """
        Derive a private key for a specific BIP-44 address.

        SECURITY WARNING
        ----------------

        This method returns extremely sensitive material.

        The returned private key MUST NOT be:

            - logged
            - printed
            - stored in the database
            - sent through HTTP
            - sent through USB transport
            - included in API responses
            - included in Django messages
            - persisted to disk

        It should only be used by the offline signing boundary.
        """

        cls._validate_indexes(
            account=account,
            change=change,
            address_index=address_index,
        )

        normalized_coin = cls.normalize_coin(
            coin
        )

        wallet = cls.root_wallet(
            seed,
            coin=normalized_coin,
        )

        try:
            account_node = (
                wallet
                .Purpose()
                .Coin()
                .Account(account)
            )

            change_type = (
                Bip44Changes.CHAIN_EXT
                if change == 0
                else Bip44Changes.CHAIN_INT
            )

            change_node = account_node.Change(
                change_type
            )

            address_node = change_node.AddressIndex(
                address_index
            )

            return (
                address_node
                .PrivateKey()
                .Raw()
                .ToBytes()
            )

        except Exception as exc:
            raise HDWalletError(
                "Unable to derive private key."
            ) from exc

    # ----------------------------------------------------------------------
    # DERIVE ADDRESS ONLY
    # ----------------------------------------------------------------------

    @classmethod
    def derive_address(
        cls,
        seed: bytes,
        *,
        coin: str = "ethereum",
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
    ) -> str:
        """
        Derive only the public blockchain address.
        """

        result = cls.derive_account(
            seed,
            coin=coin,
            account=account,
            change=change,
            address_index=address_index,
        )

        return result.address

    # ----------------------------------------------------------------------
    # INDEX VALIDATION
    # ----------------------------------------------------------------------

    @staticmethod
    def _validate_indexes(
        *,
        account: int,
        change: int,
        address_index: int,
    ) -> None:
        """
        Validate BIP-44 derivation indexes.
        """

        if isinstance(account, bool) or not isinstance(
            account,
            int,
        ):
            raise InvalidPathError(
                "Account index must be an integer."
            )

        if isinstance(change, bool) or not isinstance(
            change,
            int,
        ):
            raise InvalidPathError(
                "Change index must be an integer."
            )

        if isinstance(address_index, bool) or not isinstance(
            address_index,
            int,
        ):
            raise InvalidPathError(
                "Address index must be an integer."
            )

        if account < 0:
            raise InvalidPathError(
                "Account index cannot be negative."
            )

        if change not in {0, 1}:
            raise InvalidPathError(
                "Change must be 0 or 1."
            )

        if address_index < 0:
            raise InvalidPathError(
                "Address index cannot be negative."
            )

    # ----------------------------------------------------------------------
    # SAFE PUBLIC WALLET INFORMATION
    # ----------------------------------------------------------------------

    @classmethod
    def public_account(
        cls,
        seed: bytes,
        *,
        coin: str = "ethereum",
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
    ) -> dict[str, Any]:
        """
        Return safe public wallet information.

        The result contains:

            - coin
            - network
            - account
            - change
            - address_index
            - derivation_path
            - address
            - public_key

        It NEVER contains:

            - mnemonic
            - seed
            - private key
        """

        result = cls.derive_account(
            seed,
            coin=coin,
            account=account,
            change=change,
            address_index=address_index,
        )

        return {
            "coin": result.coin,
            "network": result.network,
            "account": result.account,
            "change": result.change,
            "address_index": result.address_index,
            "derivation_path": result.derivation_path,
            "address": result.address,
            "public_key": result.public_key,
        }


# ============================================================================
# SERVICE COMPATIBILITY
# ============================================================================

# WalletCreationService historically imports HDWalletService.
#
# Keep this compatibility name so existing imports continue to work:
#
#     from .hd_wallet import HDWalletService
#
# without maintaining two separate HD wallet implementations.

HDWalletService = HDWallet