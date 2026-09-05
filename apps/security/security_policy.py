"""
HappyWallet Security Policy.

Centralizes security rules for wallet operations.

This module does not encrypt or decrypt wallet material.
Encryption is handled by:
    apps.security.encryption
    apps.security.vault
"""

from __future__ import annotations

from dataclasses import dataclass


class SecurityPolicyError(Exception):
    """Base exception for security-policy violations."""


class InvalidSecurityPolicyError(SecurityPolicyError):
    """Raised when a security-policy configuration is invalid."""


class SecurityViolation(SecurityPolicyError):
    """Raised when an operation violates a security policy."""


@dataclass(frozen=True, slots=True)
class SecurityPolicy:
    """
    Immutable security configuration for HappyWallet.
    """

    min_password_length: int = 12
    require_confirmation_for_broadcast: bool = True
    allow_transaction_broadcast: bool = False
    require_wallet_unlock: bool = True
    require_authentication: bool = True
    max_failed_unlock_attempts: int = 5

    def __post_init__(self) -> None:
        if self.min_password_length < 12:
            raise InvalidSecurityPolicyError(
                "Minimum wallet password length cannot be less than 12."
            )

        if self.max_failed_unlock_attempts <= 0:
            raise InvalidSecurityPolicyError(
                "Maximum failed unlock attempts must be greater than zero."
            )

    def validate_password(self, password: str) -> None:
        """
        Validate a wallet password against the security policy.
        """
        if not isinstance(password, str):
            raise SecurityViolation(
                "Wallet password must be a string."
            )

        if not password:
            raise SecurityViolation(
                "Wallet password cannot be empty."
            )

        if len(password) < self.min_password_length:
            raise SecurityViolation(
                f"Wallet password must contain at least "
                f"{self.min_password_length} characters."
            )

    def require_authenticated(self, authenticated: bool) -> None:
        """
        Require an authenticated user when policy demands it.
        """
        if self.require_authentication and not authenticated:
            raise SecurityViolation(
                "Authentication is required for this operation."
            )

    def require_unlocked(self, unlocked: bool) -> None:
        """
        Require an unlocked wallet when policy demands it.
        """
        if self.require_wallet_unlock and not unlocked:
            raise SecurityViolation(
                "Wallet must be unlocked for this operation."
            )

    def validate_broadcast(
        self,
        *,
        authenticated: bool,
        wallet_unlocked: bool,
        confirmed: bool,
    ) -> None:
        """
        Validate whether a blockchain transaction may be broadcast.
        """

        self.require_authenticated(authenticated)
        self.require_unlocked(wallet_unlocked)

        if not self.allow_transaction_broadcast:
            raise SecurityViolation(
                "Transaction broadcasting is disabled by security policy."
            )

        if (
            self.require_confirmation_for_broadcast
            and not confirmed
        ):
            raise SecurityViolation(
                "Transaction confirmation is required before broadcasting."
            )


DEFAULT_SECURITY_POLICY = SecurityPolicy()


__all__ = [
    "SecurityPolicy",
    "SecurityPolicyError",
    "InvalidSecurityPolicyError",
    "SecurityViolation",
    "DEFAULT_SECURITY_POLICY",
]