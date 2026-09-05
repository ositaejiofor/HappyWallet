"""
HappyWallet Bitcoin Network Adapter.

This module contains Bitcoin-specific transaction operations.

Security boundary
-----------------

This adapter MUST NOT:

    - access private keys
    - access mnemonic phrases
    - decrypt wallet secrets
    - sign transactions
    - persist wallet secrets
    - modify wallet records

Bitcoin transaction construction, signing, and broadcasting are
separate responsibilities.
"""

from __future__ import annotations


class BitcoinNetworkError(RuntimeError):
    """Base exception for Bitcoin network adapter failures."""


__all__ = [
    "BitcoinNetworkError",
]