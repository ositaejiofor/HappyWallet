"""
HappyWallet Password Security Policy.

This module defines and enforces password and wallet-PIN policy.

Security boundary
-----------------

    User credential
          |
          v
    PasswordPolicy
          |
          +---- password rules
          |
          +---- PIN rules
          |
          v
    PasswordService
          |
          +---- PBKDF2-HMAC-SHA256
          +---- random salt
          +---- versioned verifier

Responsibilities
----------------

This module owns:

    - password policy definitions
    - PIN policy definitions
    - password validation
    - PIN validation
    - policy result reporting

This module deliberately does NOT know about:

    - Django models
    - HTTP requests
    - sessions
    - templates
    - database persistence
    - password hashing
    - encryption
    - private keys
    - wallet vaults
    - blockchain RPC

Security properties
-------------------

    - no plaintext credentials are persisted
    - no credentials are logged
    - password length is bounded
    - PIN length is bounded
    - PINs are restricted to ASCII digits
    - policy validation is deterministic
    - policy logic is independent from cryptographic implementation
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


# ============================================================================
# EXCEPTIONS
# ============================================================================


class PasswordPolicyError(ValueError):
    """
    Base exception for password-policy violations.
    """


class InvalidPasswordPolicyError(PasswordPolicyError):
    """
    Raised when a password violates the configured policy.
    """


class InvalidPinPolicyError(PasswordPolicyError):
    """
    Raised when a wallet PIN violates the configured policy.
    """


# ============================================================================
# POLICY TYPES
# ============================================================================


class CredentialType(str, Enum):
    """
    Supported credential types.
    """

    PASSWORD = "password"
    PIN = "pin"


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """
    Immutable password policy configuration.

    The policy contains no user-specific information.
    """

    min_length: int = 12
    max_length: int = 1024

    require_non_empty: bool = True

    # Optional complexity controls.

    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_special: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.min_length, int):
            raise TypeError(
                "Password minimum length must be an integer."
            )

        if not isinstance(self.max_length, int):
            raise TypeError(
                "Password maximum length must be an integer."
            )

        if self.min_length <= 0:
            raise ValueError(
                "Password minimum length must be positive."
            )

        if self.max_length <= 0:
            raise ValueError(
                "Password maximum length must be positive."
            )

        if self.min_length > self.max_length:
            raise ValueError(
                "Password minimum length cannot exceed maximum length."
            )

        for field_name in (
            "require_non_empty",
            "require_uppercase",
            "require_lowercase",
            "require_digit",
            "require_special",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(
                    f"{field_name} must be a boolean."
                )


@dataclass(frozen=True, slots=True)
class PinPolicy:
    """
    Immutable wallet-PIN policy configuration.

    PINs are intentionally restricted to ASCII digits.
    """

    min_length: int = 6
    max_length: int = 12

    ascii_digits_only: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.min_length, int):
            raise TypeError(
                "PIN minimum length must be an integer."
            )

        if not isinstance(self.max_length, int):
            raise TypeError(
                "PIN maximum length must be an integer."
            )

        if self.min_length <= 0:
            raise ValueError(
                "PIN minimum length must be positive."
            )

        if self.max_length <= 0:
            raise ValueError(
                "PIN maximum length must be positive."
            )

        if self.min_length > self.max_length:
            raise ValueError(
                "PIN minimum length cannot exceed maximum length."
            )

        if not isinstance(self.ascii_digits_only, bool):
            raise TypeError(
                "ascii_digits_only must be a boolean."
            )


# ============================================================================
# VALIDATION RESULT
# ============================================================================


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """
    Immutable result returned by non-raising policy checks.
    """

    valid: bool
    credential_type: CredentialType
    reason: str | None = None

    @classmethod
    def success(
        cls,
        credential_type: CredentialType,
    ) -> "PolicyResult":
        return cls(
            valid=True,
            credential_type=credential_type,
            reason=None,
        )

    @classmethod
    def failure(
        cls,
        credential_type: CredentialType,
        reason: str,
    ) -> "PolicyResult":
        return cls(
            valid=False,
            credential_type=credential_type,
            reason=reason,
        )


# ============================================================================
# PASSWORD POLICY SERVICE
# ============================================================================


class PasswordPolicyService:
    """
    Stateless password and PIN policy service.

    This class performs validation only.

    Cryptographic operations belong to PasswordService.
    """

    DEFAULT_PASSWORD_POLICY: Final[PasswordPolicy] = PasswordPolicy()

    DEFAULT_PIN_POLICY: Final[PinPolicy] = PinPolicy()

    SPECIAL_CHARACTERS: Final[frozenset[str]] = frozenset(
        "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\"
    )

    # ========================================================================
    # PASSWORD
    # ========================================================================

    @classmethod
    def validate_password(
        cls,
        password: str,
        *,
        policy: PasswordPolicy | None = None,
    ) -> None:
        """
        Validate a password.

        Raises:
            TypeError:
                If password is not a string.

            InvalidPasswordPolicyError:
                If the password violates policy.
        """
        active_policy = (
            policy
            if policy is not None
            else cls.DEFAULT_PASSWORD_POLICY
        )

        if not isinstance(password, str):
            raise TypeError(
                "Password must be a string."
            )

        length = len(password)

        if active_policy.require_non_empty and length == 0:
            raise InvalidPasswordPolicyError(
                "Password cannot be empty."
            )

        if length < active_policy.min_length:
            raise InvalidPasswordPolicyError(
                "Password must contain at least "
                f"{active_policy.min_length} characters."
            )

        if length > active_policy.max_length:
            raise InvalidPasswordPolicyError(
                "Password exceeds the maximum allowed length."
            )

        if (
            active_policy.require_uppercase
            and not any(character.isupper() for character in password)
        ):
            raise InvalidPasswordPolicyError(
                "Password must contain at least one uppercase character."
            )

        if (
            active_policy.require_lowercase
            and not any(character.islower() for character in password)
        ):
            raise InvalidPasswordPolicyError(
                "Password must contain at least one lowercase character."
            )

        if (
            active_policy.require_digit
            and not any(character.isdigit() for character in password)
        ):
            raise InvalidPasswordPolicyError(
                "Password must contain at least one digit."
            )

        if (
            active_policy.require_special
            and not any(
                character in cls.SPECIAL_CHARACTERS
                for character in password
            )
        ):
            raise InvalidPasswordPolicyError(
                "Password must contain at least one special character."
            )

    # ========================================================================
    # PASSWORD CHECK
    # ========================================================================

    @classmethod
    def check_password(
        cls,
        password: str,
        *,
        policy: PasswordPolicy | None = None,
    ) -> PolicyResult:
        """
        Validate a password without raising a policy exception.

        Type errors are still rejected because credential types are
        part of the API contract.
        """
        try:
            cls.validate_password(
                password,
                policy=policy,
            )
        except InvalidPasswordPolicyError as exc:
            return PolicyResult.failure(
                CredentialType.PASSWORD,
                str(exc),
            )

        return PolicyResult.success(
            CredentialType.PASSWORD
        )

    # ========================================================================
    # PIN
    # ========================================================================

    @classmethod
    def validate_pin(
        cls,
        pin: str,
        *,
        policy: PinPolicy | None = None,
    ) -> None:
        """
        Validate a wallet PIN.

        Raises:
            TypeError:
                If PIN is not a string.

            InvalidPinPolicyError:
                If the PIN violates policy.
        """
        active_policy = (
            policy
            if policy is not None
            else cls.DEFAULT_PIN_POLICY
        )

        if not isinstance(pin, str):
            raise TypeError(
                "PIN must be a string."
            )

        length = len(pin)

        if length < active_policy.min_length:
            raise InvalidPinPolicyError(
                "PIN must contain at least "
                f"{active_policy.min_length} digits."
            )

        if length > active_policy.max_length:
            raise InvalidPinPolicyError(
                "PIN exceeds the maximum allowed length."
            )

        if active_policy.ascii_digits_only:
            if not pin.isascii() or not pin.isdigit():
                raise InvalidPinPolicyError(
                    "PIN must contain only ASCII digits."
                )

    # ========================================================================
    # PIN CHECK
    # ========================================================================

    @classmethod
    def check_pin(
        cls,
        pin: str,
        *,
        policy: PinPolicy | None = None,
    ) -> PolicyResult:
        """
        Validate a PIN without raising a policy exception.
        """
        try:
            cls.validate_pin(
                pin,
                policy=policy,
            )
        except InvalidPinPolicyError as exc:
            return PolicyResult.failure(
                CredentialType.PIN,
                str(exc),
            )

        return PolicyResult.success(
            CredentialType.PIN
        )


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "CredentialType",
    "InvalidPasswordPolicyError",
    "InvalidPinPolicyError",
    "PasswordPolicy",
    "PasswordPolicyError",
    "PasswordPolicyService",
    "PinPolicy",
    "PolicyResult",
]