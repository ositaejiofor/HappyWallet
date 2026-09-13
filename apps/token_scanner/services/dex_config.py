from __future__ import annotations

from .dexy import DexFactory


# Ethereum Mainnet
#
# Official Uniswap V2 deployment:
# https://developers.uniswap.org/docs/protocols/v2/deployments
#
# This is deliberately explicit. The scanner must never invent or
# dynamically guess DEX factory addresses.
UNISWAP_V2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"


ETHEREUM_DEX_FACTORIES: tuple[DexFactory, ...] = (
    DexFactory(
        name="Uniswap V2",
        address=UNISWAP_V2_FACTORY,
    ),
)


__all__ = [
    "ETHEREUM_DEX_FACTORIES",
    "UNISWAP_V2_FACTORY",
]
