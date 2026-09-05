"""
HappyWallet Tron Network Adapter.

This module is reserved for TRON-specific blockchain operations.

Security boundary
-----------------

This adapter MUST NOT:

    - access private keys
    - access mnemonic phrases
    - decrypt wallet secrets
    - sign transactions
    - persist wallet secrets
    - modify wallet records

Transaction construction, signing, broadcasting, and history retrieval
remain separate responsibilities.

TRON-specific implementations should be added here when TRON support
is enabled.
"""

from __future__ import annotations


class TronNetworkError(RuntimeError):
    """Base exception for TRON network adapter failures."""


__all__ = [
    "TronNetworkError",
]