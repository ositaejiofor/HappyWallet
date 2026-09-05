"""
HappyWallet Wallet Address Derivation Service.

Application-independent cryptographic boundary for deriving public
blockchain addresses from BIP-39 recovery phrases.

Security boundary
-----------------
This module:

- never accesses Django models
- never writes to the database
- never persists recovery phrases
- never persists seeds
- never persists private keys
- never returns private keys
- never signs transactions
- never broadcasts transactions

Only public address information is returned.

Supported networks
------------------
- Ethereum Mainnet
- Bitcoin Mainnet

Derivation standard
-------------------
BIP-44:

    m/44'/coin_type'/account'/change/address_index
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)


# ============================================================================
# PUBLIC RESULT
# ============================================================================


@dataclass(frozen=True, slots=True)
class DerivedAddress:
    """
    Public information produced by wallet address derivation.

    No seed, mnemonic, private key, or other secret material is exposed.
    """

    address: str
    derivation_path: str


# ============================================================================
# DERIVATION SERVICE
# ============================================================================


class DerivationService:
    """
    Derive public blockchain addresses from BIP-39 recovery phrases.

    This service contains cryptographic derivation logic only. It has
    deliberately no dependency on Django models or persistence.

    Security
    --------
    Sensitive recovery material is used only in memory for the duration
    of derivation.

    Private keys are never returned.
    """

    # ========================================================================
    # CANONICAL NETWORK IDENTIFIERS
    # ========================================================================

    ETHEREUM = "ethereum"
    BITCOIN = "bitcoin"

    # ========================================================================
    # SUPPORTED NETWORKS
    # ========================================================================

    SUPPORTED_NETWORKS: Final = {
        ETHEREUM: Bip44Coins.ETHEREUM,
        BITCOIN: Bip44Coins.BITCOIN,
    }

    # ========================================================================
    # NETWORK ALIASES
    # ========================================================================

    NETWORK_ALIASES: Final = {
        # Ethereum
        "eth": ETHEREUM,
        "ethereum": ETHEREUM,
        "ethereum-mainnet": ETHEREUM,
        "ethereum mainnet": ETHEREUM,
        "eth-mainnet": ETHEREUM,
        "eth mainnet": ETHEREUM,

        # Bitcoin
        "btc": BITCOIN,
        "bitcoin": BITCOIN,
        "bitcoin-mainnet": BITCOIN,
        "bitcoin mainnet": BITCOIN,
        "btc-mainnet": BITCOIN,
        "btc mainnet": BITCOIN,
    }

    # ========================================================================
    # BIP-44 COIN TYPES
    # ========================================================================

    COIN_TYPES: Final = {
        ETHEREUM: 60,
        BITCOIN: 0,
    }

    # ========================================================================
    # BIP-44 LIMITS
    # ========================================================================

    MAX_BIP44_INDEX: Final = 2**31 - 1

    # ========================================================================
    # PUBLIC API
    # ========================================================================

    def derive(
        self,
        *,
        mnemonic: str,
        network: str,
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        passphrase: str = "",
    ) -> DerivedAddress:
        """
        Derive a public blockchain address.

        Parameters
        ----------
        mnemonic:
            BIP-39 recovery phrase.

        network:
            Supported network name or alias.

        account:
            BIP-44 account index.

        change:
            0 for external/receiving addresses.
            1 for internal/change addresses.

        address_index:
            Address index within the selected account/change chain.

        passphrase:
            Optional BIP-39 passphrase.

        Returns
        -------
        DerivedAddress
            Public address and derivation path only.

        Raises
        ------
        ValueError
            If an input is invalid, the network is unsupported, or
            derivation fails.
        """

        # --------------------------------------------------------------------
        # Validate non-sensitive parameters first.
        # --------------------------------------------------------------------

        self._validate_indexes(
            account=account,
            change=change,
            address_index=address_index,
        )

        network_key = self.normalize_network(
            network,
        )

        self._validate_passphrase(
            passphrase,
        )

        self._validate_mnemonic(
            mnemonic,
        )

        # --------------------------------------------------------------------
        # Generate the BIP-39 seed.
        #
        # The seed exists only in memory for the derivation operation.
        # --------------------------------------------------------------------

        seed = self._generate_seed(
            mnemonic=mnemonic,
            passphrase=passphrase,
        )

        try:
            coin = self.SUPPORTED_NETWORKS[
                network_key
            ]

            coin_type = self.COIN_TYPES[
                network_key
            ]

            return self._derive(
                seed=seed,
                coin=coin,
                coin_type=coin_type,
                account=account,
                change=change,
                address_index=address_index,
            )

        except ValueError:
            raise

        except Exception as exc:
            raise ValueError(
                "Unable to derive blockchain address."
            ) from exc

        finally:
            # Python does not guarantee memory zeroization.
            #
            # Removing our reference immediately after derivation
            # nevertheless limits the lifetime of the seed in this scope.
            del seed

    # ========================================================================
    # NETWORK NORMALIZATION
    # ========================================================================

    @classmethod
    def normalize_network(
        cls,
        network: str,
    ) -> str:
        """
        Normalize a supported network name or alias.

        Examples
        --------
        ETH
            -> ethereum

        Ethereum Mainnet
            -> ethereum

        ethereum-mainnet
            -> ethereum

        BTC
            -> bitcoin

        Bitcoin Mainnet
            -> bitcoin
        """

        if not isinstance(network, str):
            raise ValueError(
                "Blockchain network must be a string."
            )

        normalized = " ".join(
            network.strip().lower().split()
        )

        if not normalized:
            raise ValueError(
                "Blockchain network is required."
            )

        # Exact alias match.
        network_key = cls.NETWORK_ALIASES.get(
            normalized,
        )

        if network_key is not None:
            return network_key

        # Also support normalized hyphenated forms.
        hyphenated = normalized.replace(
            " ",
            "-",
        )

        network_key = cls.NETWORK_ALIASES.get(
            hyphenated,
        )

        if network_key is not None:
            return network_key

        supported = ", ".join(
            sorted(
                cls.SUPPORTED_NETWORKS,
            )
        )

        raise ValueError(
            f"Unsupported blockchain network: {network}. "
            f"Supported networks: {supported}."
        )

    # ========================================================================
    # INPUT VALIDATION
    # ========================================================================

    @staticmethod
    def _validate_mnemonic(
        mnemonic: str,
    ) -> None:
        """
        Validate the basic recovery-phrase input.

        Full BIP-39 validation is delegated to bip_utils during
        seed generation.
        """

        if not isinstance(
            mnemonic,
            str,
        ):
            raise ValueError(
                "Mnemonic must be a string."
            )

        if not mnemonic.strip():
            raise ValueError(
                "A mnemonic is required."
            )

    @staticmethod
    def _validate_passphrase(
        passphrase: str,
    ) -> None:
        """
        Validate the optional BIP-39 passphrase.
        """

        if not isinstance(
            passphrase,
            str,
        ):
            raise ValueError(
                "BIP-39 passphrase must be a string."
            )

    @classmethod
    def _validate_indexes(
        cls,
        *,
        account: int,
        change: int,
        address_index: int,
    ) -> None:
        """
        Validate BIP-44 derivation indexes.

        Account and address indexes must remain within the BIP-44
        non-hardened/hardened index boundary.

        Change is restricted to the standard BIP-44 external/internal
        chains.
        """

        if (
            not isinstance(account, int)
            or isinstance(account, bool)
            or account < 0
            or account > cls.MAX_BIP44_INDEX
        ):
            raise ValueError(
                "Account must be an integer between "
                "0 and 2147483647."
            )

        if (
            not isinstance(change, int)
            or isinstance(change, bool)
            or change not in (0, 1)
        ):
            raise ValueError(
                "Change must be either 0 or 1."
            )

        if (
            not isinstance(address_index, int)
            or isinstance(address_index, bool)
            or address_index < 0
            or address_index > cls.MAX_BIP44_INDEX
        ):
            raise ValueError(
                "Address index must be an integer between "
                "0 and 2147483647."
            )

    # ========================================================================
    # BIP-39 SEED
    # ========================================================================

    @staticmethod
    def _generate_seed(
        *,
        mnemonic: str,
        passphrase: str = "",
    ) -> bytes:
        """
        Convert a BIP-39 recovery phrase into a binary seed.

        The seed is returned only to the immediate derivation pipeline
        and is never persisted.
        """

        try:
            return Bip39SeedGenerator(
                mnemonic.strip(),
            ).Generate(
                passphrase,
            )

        except Exception as exc:
            raise ValueError(
                "Invalid recovery phrase."
            ) from exc

    # ========================================================================
    # CHANGE CHAIN
    # ========================================================================

    @staticmethod
    def _get_change_type(
        change: int,
    ) -> Bip44Changes:
        """
        Convert the public change index into bip_utils format.
        """

        if change == 0:
            return Bip44Changes.CHAIN_EXT

        if change == 1:
            return Bip44Changes.CHAIN_INT

        raise ValueError(
            "Change must be either 0 or 1."
        )

    # ========================================================================
    # BIP-44 DERIVATION
    # ========================================================================

    @classmethod
    def _derive(
        cls,
        *,
        seed: bytes,
        coin,
        coin_type: int,
        account: int,
        change: int,
        address_index: int,
    ) -> DerivedAddress:
        """
        Perform standard BIP-44 public address derivation.

        Path:

            m/44'/coin_type'/account'/change/address_index

        Only the resulting public address and path are returned.
        """

        wallet = Bip44.FromSeed(
            seed,
            coin,
        )

        address_node = (
            wallet
            .Purpose()
            .Coin()
            .Account(account)
            .Change(
                cls._get_change_type(
                    change,
                )
            )
            .AddressIndex(
                address_index,
            )
        )

        address = (
            address_node
            .PublicKey()
            .ToAddress()
        )

        if not address:
            raise ValueError(
                "Address derivation returned an empty address."
            )

        derivation_path = cls._build_path(
            coin_type=coin_type,
            account=account,
            change=change,
            address_index=address_index,
        )

        return DerivedAddress(
            address=address,
            derivation_path=derivation_path,
        )

    # ========================================================================
    # DERIVATION PATH
    # ========================================================================

    @staticmethod
    def _build_path(
        *,
        coin_type: int,
        account: int,
        change: int,
        address_index: int,
    ) -> str:
        """
        Build the canonical BIP-44 derivation path.
        """

        return (
            f"m/44'/{coin_type}'/"
            f"{account}'/{change}/"
            f"{address_index}"
        )


# ============================================================================
# DEFAULT SERVICE
# ============================================================================


derivation_service = DerivationService()


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================


def derive_address(
    *,
    mnemonic: str,
    network: str,
    account: int = 0,
    change: int = 0,
    address_index: int = 0,
    passphrase: str = "",
) -> DerivedAddress:
    """
    Convenience wrapper around the default DerivationService.
    """

    return derivation_service.derive(
        mnemonic=mnemonic,
        network=network,
        account=account,
        change=change,
        address_index=address_index,
        passphrase=passphrase,
    )