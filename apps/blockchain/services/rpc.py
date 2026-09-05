# apps/blockchain/services/rpc.py

from __future__ import annotations

from django.conf import settings


class BlockchainRPCService:
    """
    Resolve blockchain RPC endpoints from Django settings.

    RPC credentials must come from environment variables.
    They should not be hard-coded in application source code.
    """

    NETWORK_RPC_SETTINGS = {
        "ethereum": "ETHEREUM_RPC_URL",
        "ethereum-mainnet": "ETHEREUM_RPC_URL",
        "bitcoin": "BITCOIN_RPC_URL",
        "bitcoin-mainnet": "BITCOIN_RPC_URL",
        "tron": "TRON_RPC_URL",
        "tron-mainnet": "TRON_RPC_URL",
    }

    @classmethod
    def get_rpc_url(
        cls,
        *,
        network_slug: str,
    ) -> str:
        if not isinstance(network_slug, str):
            raise ValueError(
                "Blockchain network must be a string."
            )

        slug = network_slug.strip().lower()

        if not slug:
            raise ValueError(
                "Blockchain network is required."
            )

        setting_name = cls.NETWORK_RPC_SETTINGS.get(
            slug
        )

        if setting_name is None:
            raise ValueError(
                f"Unsupported blockchain network: {network_slug}"
            )

        rpc_url = getattr(
            settings,
            setting_name,
            "",
        )

        return (
            rpc_url.strip()
            if isinstance(rpc_url, str)
            else ""
        )