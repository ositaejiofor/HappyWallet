# apps/blockchain/services/network.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from django.conf import settings
from django.db.models import QuerySet

from apps.blockchain.models import BlockchainNetwork


@dataclass(frozen=True, slots=True)
class BlockchainNetworkConfiguration:
    """
    Immutable runtime configuration for a blockchain network.

    Contains public network metadata and the RPC endpoint required
    for read-only blockchain communication.
    """

    network: BlockchainNetwork

    name: str
    slug: str
    symbol: str

    chain_id: int | None

    rpc_url: str
    explorer_url: str

    is_testnet: bool
    is_active: bool


class BlockchainNetworkService:
    """
    Resolve blockchain network configuration.

    Responsibilities
    ----------------
    - Resolve database blockchain networks.
    - Normalize network identifiers.
    - Validate network state.
    - Resolve RPC endpoints.
    - Expose active networks.

    Security
    --------
    This service never:

    - handles mnemonics
    - handles private keys
    - derives wallet addresses
    - signs transactions
    - broadcasts transactions
    - stores blockchain balances
    - modifies wallet records
    """

    # =========================================================================
    # NETWORK DEFINITIONS
    # =========================================================================

    NETWORK_ALIASES: Final[dict[str, str]] = {
        # Ethereum
        "eth": "ethereum-mainnet",
        "ethereum": "ethereum-mainnet",
        "ethereum mainnet": "ethereum-mainnet",
        "ethereum-mainnet": "ethereum-mainnet",

        # Bitcoin
        "btc": "bitcoin-mainnet",
        "bitcoin": "bitcoin-mainnet",
        "bitcoin mainnet": "bitcoin-mainnet",
        "bitcoin-mainnet": "bitcoin-mainnet",

        # Tron
        "trx": "tron-mainnet",
        "tron": "tron-mainnet",
        "tron mainnet": "tron-mainnet",
        "tron-mainnet": "tron-mainnet",
    }

    RPC_SETTINGS: Final[dict[str, str]] = {
        "ethereum-mainnet": "ETHEREUM_RPC_URL",
        "bitcoin-mainnet": "BITCOIN_RPC_URL",
        "tron-mainnet": "TRON_RPC_URL",
    }

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def get(
        self,
        *,
        network: BlockchainNetwork,
    ) -> BlockchainNetworkConfiguration:
        """
        Resolve a database BlockchainNetwork into runtime configuration.

        Raises
        ------
        ValueError
            If the network is invalid, inactive, or has no RPC configured.
        """

        self._validate_network(network)

        return BlockchainNetworkConfiguration(
            network=network,
            name=self._clean(network.name),
            slug=self.normalize_slug(network.slug),
            symbol=self._clean(network.symbol),
            chain_id=network.chain_id,
            rpc_url=self.get_rpc_url(network=network),
            explorer_url=self._clean(network.explorer_url),
            is_testnet=bool(network.is_testnet),
            is_active=bool(network.is_active),
        )

    # =========================================================================
    # DATABASE LOOKUPS
    # =========================================================================

    def get_by_slug(
        self,
        *,
        slug: str,
    ) -> BlockchainNetworkConfiguration:
        """
        Resolve an active blockchain network by slug or alias.
        """

        normalized_slug = self.normalize_slug(slug)

        network = (
            BlockchainNetwork.objects
            .filter(
                slug=normalized_slug,
                is_active=True,
            )
            .first()
        )

        if network is None:
            raise ValueError(
                f"Unsupported blockchain network: {slug}"
            )

        return self.get(network=network)

    def get_by_chain_id(
        self,
        *,
        chain_id: int,
    ) -> BlockchainNetworkConfiguration:
        """
        Resolve an active blockchain network by chain ID.
        """

        self._validate_chain_id(chain_id)

        network = (
            BlockchainNetwork.objects
            .filter(
                chain_id=chain_id,
                is_active=True,
            )
            .first()
        )

        if network is None:
            raise ValueError(
                f"Unsupported blockchain chain ID: {chain_id}"
            )

        return self.get(network=network)

    def get_active_networks(
        self,
    ) -> QuerySet[BlockchainNetwork]:
        """
        Return all active blockchain networks.

        The queryset remains lazy.
        """

        return (
            BlockchainNetwork.objects
            .filter(is_active=True)
            .order_by("name")
        )

    # =========================================================================
    # NETWORK NORMALIZATION
    # =========================================================================

    @classmethod
    def normalize_slug(
        cls,
        value: str,
    ) -> str:
        """
        Normalize a network name, symbol, or slug.

        Examples
        --------
        ETH
            -> ethereum-mainnet

        Ethereum Mainnet
            -> ethereum-mainnet

        bitcoin
            -> bitcoin-mainnet
        """

        if not isinstance(value, str):
            raise ValueError(
                "Blockchain network must be a string."
            )

        normalized = " ".join(
            value.strip().lower().split()
        )

        if not normalized:
            raise ValueError(
                "Blockchain network is required."
            )

        return cls.NETWORK_ALIASES.get(
            normalized,
            normalized.replace(" ", "-"),
        )

    # =========================================================================
    # RPC RESOLUTION
    # =========================================================================

    def get_rpc_url(
        self,
        *,
        network: BlockchainNetwork,
    ) -> str:
        """
        Resolve the RPC URL for a blockchain network.

        Priority
        --------
        1. Django settings/environment.
        2. Database rpc_url.

        Environment configuration is preferred because RPC URLs can
        contain provider credentials or API keys.
        """

        self._validate_network(
            network,
            require_rpc=False,
        )

        slug = self.normalize_slug(network.slug)

        setting_name = self.RPC_SETTINGS.get(slug)

        if setting_name:
            configured_rpc = self._clean(
                getattr(
                    settings,
                    setting_name,
                    "",
                )
            )

            if configured_rpc:
                return configured_rpc

        database_rpc = self._clean(
            network.rpc_url,
        )

        if database_rpc:
            return database_rpc

        raise ValueError(
            f"No RPC URL configured for '{network.name}'."
        )

    def is_rpc_configured(
        self,
        *,
        network: BlockchainNetwork,
    ) -> bool:
        """
        Return True when an RPC endpoint is available.
        """

        try:
            self.get_rpc_url(
                network=network,
            )
        except ValueError:
            return False

        return True

    # =========================================================================
    # VALIDATION
    # =========================================================================

    @staticmethod
    def _validate_network(
        network: BlockchainNetwork,
        *,
        require_rpc: bool = True,
    ) -> None:
        """
        Validate a BlockchainNetwork instance.
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
                "Invalid blockchain network."
            )

        if not network.is_active:
            raise ValueError(
                f"Blockchain network is inactive: {network.name}"
            )

        if require_rpc:
            # Do not resolve all possible RPC providers here.
            # get_rpc_url() performs network-specific resolution.
            if not (
                network.rpc_url
                or BlockchainNetworkService._environment_rpc_exists(
                    network
                )
            ):
                raise ValueError(
                    f"No RPC configuration available for "
                    f"'{network.name}'."
                )

    @classmethod
    def _environment_rpc_exists(
        cls,
        network: BlockchainNetwork,
    ) -> bool:
        """
        Check whether the environment contains an RPC URL for
        the specific network.
        """

        slug = cls.normalize_slug(
            network.slug,
        )

        setting_name = cls.RPC_SETTINGS.get(
            slug,
        )

        if not setting_name:
            return False

        return bool(
            cls._clean(
                getattr(
                    settings,
                    setting_name,
                    "",
                )
            )
        )

    @staticmethod
    def _validate_chain_id(
        chain_id: int,
    ) -> None:
        """
        Validate a blockchain chain ID.
        """

        if (
            not isinstance(chain_id, int)
            or isinstance(chain_id, bool)
        ):
            raise ValueError(
                "Chain ID must be an integer."
            )

        if chain_id <= 0:
            raise ValueError(
                "Chain ID must be a positive integer."
            )

    # =========================================================================
    # STRING HELPERS
    # =========================================================================

    @staticmethod
    def _clean(
        value: str | None,
    ) -> str:
        """
        Safely normalize an optional string.
        """

        if not isinstance(value, str):
            return ""

        return value.strip()


# =============================================================================
# DEFAULT SERVICE
# =============================================================================

blockchain_network_service = BlockchainNetworkService()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_network_configuration(
    network: BlockchainNetwork,
) -> BlockchainNetworkConfiguration:
    """
    Resolve a BlockchainNetwork instance.
    """

    return blockchain_network_service.get(
        network=network,
    )


def get_network_by_slug(
    slug: str,
) -> BlockchainNetworkConfiguration:
    """
    Resolve a blockchain network by slug or alias.
    """

    return blockchain_network_service.get_by_slug(
        slug=slug,
    )


def get_network_by_chain_id(
    chain_id: int,
) -> BlockchainNetworkConfiguration:
    """
    Resolve a blockchain network by chain ID.
    """

    return blockchain_network_service.get_by_chain_id(
        chain_id=chain_id,
    )


def get_active_networks() -> QuerySet[BlockchainNetwork]:
    """
    Return all active blockchain networks.
    """

    return blockchain_network_service.get_active_networks()


def get_network_rpc_url(
    network: BlockchainNetwork,
) -> str:
    """
    Return the configured RPC URL for a network.
    """

    return blockchain_network_service.get_rpc_url(
        network=network,
    )


def is_network_rpc_configured(
    network: BlockchainNetwork,
) -> bool:
    """
    Return True when an RPC URL is configured.
    """

    return blockchain_network_service.is_rpc_configured(
        network=network,
    )
