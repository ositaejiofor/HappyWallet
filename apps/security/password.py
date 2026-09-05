"""
HappyWallet Password and PIN Security Service.

Security boundary
-----------------

    Password / PIN
          |
          v
    PasswordService
          |
          +---- random salt
          |
          +---- PBKDF2-HMAC-SHA256
          |
          v
    Versioned password verifier

Responsibilities
----------------
This module owns:

    - password/PIN validation
    - password hashing
    - password verification
    - versioned hash serialization
    - constant-time verification
    - password policy enforcement

This module deliberately does NOT know about:

    - Django models
    - HTTP requests
    - sessions
    - templates
    - wallet vault encryption
    - private keys
    - blockchain RPC
    - filesystem persistence

Security properties
-------------------
    - plaintext passwords are never persisted
    - plaintext passwords are never logged
    - random salt is generated for every password/PIN
    - password verification uses constant-time comparison
    - malformed password hashes are rejected
    - unsupported hash versions are rejected
    - algorithm parameters are encoded in the verifier
    - password hashes are safe to store as strings
    - password-hash records are immutable
    - password policy is enforced before derivation
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import ClassVar, Final


# ============================================================================
# CONSTANTS
# ============================================================================


_PASSWORD_HASH_PREFIX: Final[str] = "hw-pwd"


# ============================================================================
# EXCEPTIONS
# ============================================================================


class PasswordSecurityError(Exception):
    """Base exception for password security failures."""


class InvalidPasswordError(PasswordSecurityError):
    """Raised when a password or PIN violates security policy."""


class InvalidPasswordHashError(PasswordSecurityError):
    """Raised when a stored password verifier is malformed or unsupported."""


# ============================================================================
# PASSWORD HASH
# ============================================================================


@dataclass(frozen=True, slots=True)
class PasswordHash:
    """
    Immutable password verifier.

    The plaintext password is never stored.

    Instance fields
    ---------------

    version:
        Password verifier format version.

    algorithm:
        Password derivation algorithm.

    iterations:
        PBKDF2 iteration count.

    salt:
        Random cryptographic salt.

    digest:
        Derived password digest.

    Class constants
    ---------------

    VERSION:
        Current password verifier format version.

    ALGORITHM:
        Current password derivation algorithm.

    SALT_SIZE:
        Required salt size in bytes.

    DIGEST_SIZE:
        Required derived digest size in bytes.
    """

    # ------------------------------------------------------------------------
    # INSTANCE FIELDS
    # ------------------------------------------------------------------------

    version: int
    algorithm: str
    iterations: int
    salt: bytes
    digest: bytes

    # ------------------------------------------------------------------------
    # CLASS-LEVEL SECURITY PARAMETERS
    #
    # ClassVar is important here.
    #
    # Without ClassVar, dataclasses treats these values as fields. Combined
    # with slots=True, PasswordHash.SALT_SIZE can become a member descriptor
    # instead of the integer 16.
    # ------------------------------------------------------------------------

    VERSION: ClassVar[int] = 1

    ALGORITHM: ClassVar[str] = "PBKDF2-HMAC-SHA256"

    SALT_SIZE: ClassVar[int] = 16

    DIGEST_SIZE: ClassVar[int] = 32

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def __post_init__(self) -> None:
        """Validate the complete immutable verifier."""

        if not isinstance(self.version, int):
            raise TypeError(
                "Password hash version must be an integer."
            )

        if self.version != self.VERSION:
            raise ValueError(
                "Unsupported password hash version."
            )

        if not isinstance(self.algorithm, str):
            raise TypeError(
                "Password hash algorithm must be a string."
            )

        if self.algorithm != self.ALGORITHM:
            raise ValueError(
                "Unsupported password hash algorithm."
            )

        if not isinstance(self.iterations, int):
            raise TypeError(
                "Password hash iterations must be an integer."
            )

        if self.iterations <= 0:
            raise ValueError(
                "Password hash iterations must be positive."
            )

        if not isinstance(self.salt, bytes):
            raise TypeError(
                "Password hash salt must be bytes."
            )

        if len(self.salt) != self.SALT_SIZE:
            raise ValueError(
                f"Password hash salt must be "
                f"{self.SALT_SIZE} bytes."
            )

        if not isinstance(self.digest, bytes):
            raise TypeError(
                "Password hash digest must be bytes."
            )

        if len(self.digest) != self.DIGEST_SIZE:
            raise ValueError(
                f"Password hash digest must be "
                f"{self.DIGEST_SIZE} bytes."
            )

    # ========================================================================
    # SERIALIZATION
    # ========================================================================

    def serialize(self) -> str:
        """
        Serialize the password verifier.

        Format:

            hw-pwd$version$algorithm$iterations$salt$digest

        Salt and digest are Base64 encoded.
        """

        encoded_salt = base64.b64encode(
            self.salt
        ).decode("ascii")

        encoded_digest = base64.b64encode(
            self.digest
        ).decode("ascii")

        return (
            f"{_PASSWORD_HASH_PREFIX}$"
            f"{self.version}$"
            f"{self.algorithm}$"
            f"{self.iterations}$"
            f"{encoded_salt}$"
            f"{encoded_digest}"
        )

    @classmethod
    def deserialize(
        cls,
        value: str,
    ) -> "PasswordHash":
        """
        Deserialize a stored password verifier.

        All malformed verifier data is normalized into
        InvalidPasswordHashError.
        """

        if not isinstance(value, str):
            raise InvalidPasswordHashError(
                "Password hash must be a string."
            )

        if not value:
            raise InvalidPasswordHashError(
                "Password hash cannot be empty."
            )

        parts = value.split("$")

        if len(parts) != 6:
            raise InvalidPasswordHashError(
                "Invalid password hash format."
            )

        (
            prefix,
            version,
            algorithm,
            iterations,
            salt,
            digest,
        ) = parts

        if prefix != _PASSWORD_HASH_PREFIX:
            raise InvalidPasswordHashError(
                "Unsupported password hash format."
            )

        try:
            parsed_version = int(version)
            parsed_iterations = int(iterations)
        except (TypeError, ValueError) as exc:
            raise InvalidPasswordHashError(
                "Invalid password hash metadata."
            ) from exc

        try:
            decoded_salt = base64.b64decode(
                salt,
                validate=True,
            )

            decoded_digest = base64.b64decode(
                digest,
                validate=True,
            )

        except (
            binascii.Error,
            ValueError,
        ) as exc:
            raise InvalidPasswordHashError(
                "Invalid password hash encoding."
            ) from exc

        try:
            return cls(
                version=parsed_version,
                algorithm=algorithm,
                iterations=parsed_iterations,
                salt=decoded_salt,
                digest=decoded_digest,
            )

        except (
            TypeError,
            ValueError,
        ) as exc:
            raise InvalidPasswordHashError(
                "Invalid password hash."
            ) from exc


# ============================================================================
# PASSWORD SERVICE
# ============================================================================


class PasswordService:
    """
    Password and wallet-PIN hashing service.

    PBKDF2-HMAC-SHA256 is used for one-way password/PIN verification.

    This service is intentionally separate from EncryptionService.

    EncryptionService:

        password -> encryption key -> AES-GCM

    PasswordService:

        password -> one-way verifier
    """

    # ========================================================================
    # ALGORITHM
    # ========================================================================

    ALGORITHM: Final[str] = PasswordHash.ALGORITHM

    VERSION: Final[int] = PasswordHash.VERSION

    # ========================================================================
    # KDF PARAMETERS
    # ========================================================================

    ITERATIONS: Final[int] = 600_000

    SALT_SIZE: Final[int] = PasswordHash.SALT_SIZE

    DIGEST_SIZE: Final[int] = PasswordHash.DIGEST_SIZE

    # ========================================================================
    # PASSWORD POLICY
    # ========================================================================

    MIN_PASSWORD_LENGTH: Final[int] = 12

    MAX_PASSWORD_LENGTH: Final[int] = 1024

    # ========================================================================
    # PIN POLICY
    # ========================================================================

    MIN_PIN_LENGTH: Final[int] = 6

    MAX_PIN_LENGTH: Final[int] = 12

    # ========================================================================
    # PASSWORD VALIDATION
    # ========================================================================

    @classmethod
    def validate_password(
        cls,
        password: str,
    ) -> None:
        """
        Validate a wallet password.

        Requirements:

            - string
            - non-empty
            - minimum 12 characters
            - maximum 1024 characters
        """

        if not isinstance(password, str):
            raise TypeError(
                "Password must be a string."
            )

        length = len(password)

        if length == 0:
            raise InvalidPasswordError(
                "Password cannot be empty."
            )

        if length < cls.MIN_PASSWORD_LENGTH:
            raise InvalidPasswordError(
                "Password must contain at least "
                f"{cls.MIN_PASSWORD_LENGTH} characters."
            )

        if length > cls.MAX_PASSWORD_LENGTH:
            raise InvalidPasswordError(
                "Password exceeds the maximum allowed length."
            )

    # ========================================================================
    # PIN VALIDATION
    # ========================================================================

    @classmethod
    def validate_pin(
        cls,
        pin: str,
    ) -> None:
        """
        Validate a wallet PIN.

        PINs are restricted to ASCII digits.

        Requirements:

            - string
            - digits only
            - 6-12 digits
        """

        if not isinstance(pin, str):
            raise TypeError(
                "PIN must be a string."
            )

        length = len(pin)

        if length < cls.MIN_PIN_LENGTH:
            raise InvalidPasswordError(
                "PIN must contain at least "
                f"{cls.MIN_PIN_LENGTH} digits."
            )

        if length > cls.MAX_PIN_LENGTH:
            raise InvalidPasswordError(
                "PIN exceeds the maximum allowed length."
            )

        if not pin.isascii() or not pin.isdigit():
            raise InvalidPasswordError(
                "PIN must contain only ASCII digits."
            )

    # ========================================================================
    # HASH PASSWORD
    # ========================================================================

    @classmethod
    def hash_password(
        cls,
        password: str,
    ) -> str:
        """
        Create a password verifier.

        The plaintext password is never persisted or returned.
        """

        cls.validate_password(password)

        salt = os.urandom(cls.SALT_SIZE)

        digest = cls._derive(
            password=password,
            salt=salt,
            iterations=cls.ITERATIONS,
        )

        password_hash = PasswordHash(
            version=cls.VERSION,
            algorithm=cls.ALGORITHM,
            iterations=cls.ITERATIONS,
            salt=salt,
            digest=digest,
        )

        return password_hash.serialize()

    # ========================================================================
    # HASH PIN
    # ========================================================================

    @classmethod
    def hash_pin(
        cls,
        pin: str,
    ) -> str:
        """
        Create a one-way verifier for a wallet PIN.

        A unique cryptographically secure random salt is generated
        for every PIN.
        """

        cls.validate_pin(pin)

        salt = os.urandom(cls.SALT_SIZE)

        digest = cls._derive(
            password=pin,
            salt=salt,
            iterations=cls.ITERATIONS,
        )

        password_hash = PasswordHash(
            version=cls.VERSION,
            algorithm=cls.ALGORITHM,
            iterations=cls.ITERATIONS,
            salt=salt,
            digest=digest,
        )

        return password_hash.serialize()

    # ========================================================================
    # VERIFY PASSWORD
    # ========================================================================

    @classmethod
    def verify_password(
        cls,
        password: str,
        stored_hash: str,
    ) -> bool:
        """
        Verify a password against a stored verifier.

        Returns:

            True:
                Password is correct.

            False:
                Password is incorrect.

        Raises:

            InvalidPasswordError:
                Supplied password violates policy.

            InvalidPasswordHashError:
                Stored verifier is malformed or unsupported.
        """

        cls.validate_password(password)

        password_hash = PasswordHash.deserialize(
            stored_hash
        )

        derived = cls._derive(
            password=password,
            salt=password_hash.salt,
            iterations=password_hash.iterations,
        )

        return hmac.compare_digest(
            derived,
            password_hash.digest,
        )

    # ========================================================================
    # VERIFY PIN
    # ========================================================================

    @classmethod
    def verify_pin(
        cls,
        pin: str,
        stored_hash: str,
    ) -> bool:
        """
        Verify a wallet PIN against a stored verifier.

        Returns False for an incorrect PIN.

        Malformed stored verifiers raise
        InvalidPasswordHashError.
        """

        cls.validate_pin(pin)

        password_hash = PasswordHash.deserialize(
            stored_hash
        )

        derived = cls._derive(
            password=pin,
            salt=password_hash.salt,
            iterations=password_hash.iterations,
        )

        return hmac.compare_digest(
            derived,
            password_hash.digest,
        )

    # ========================================================================
    # HASH PARAMETER INSPECTION
    # ========================================================================

    @classmethod
    def needs_rehash(
        cls,
        stored_hash: str,
    ) -> bool:
        """
        Determine whether a stored verifier should be upgraded.

        This permits future algorithm or cost migrations without
        immediately invalidating existing credentials.
        """

        password_hash = PasswordHash.deserialize(
            stored_hash
        )

        return (
            password_hash.version != cls.VERSION
            or password_hash.algorithm != cls.ALGORITHM
            or password_hash.iterations != cls.ITERATIONS
            or len(password_hash.salt) != cls.SALT_SIZE
            or len(password_hash.digest) != cls.DIGEST_SIZE
        )

    # ========================================================================
    # INTERNAL DERIVATION
    # ========================================================================

    @classmethod
    def _derive(
        cls,
        *,
        password: str,
        salt: bytes,
        iterations: int,
    ) -> bytes:
        """
        Derive a password digest using PBKDF2-HMAC-SHA256.

        This method is intentionally private and is not responsible
        for validating password policy. Public hashing/verification
        methods perform password/PIN validation separately.
        """

        if not isinstance(password, str):
            raise TypeError(
                "Password material must be a string."
            )

        if not isinstance(salt, bytes):
            raise TypeError(
                "Salt must be bytes."
            )

        if len(salt) != cls.SALT_SIZE:
            raise ValueError(
                f"Salt must be exactly "
                f"{cls.SALT_SIZE} bytes."
            )

        if not isinstance(iterations, int):
            raise TypeError(
                "Iterations must be an integer."
            )

        if iterations <= 0:
            raise ValueError(
                "Iterations must be positive."
            )

        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=cls.DIGEST_SIZE,
        )


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "InvalidPasswordError",
    "InvalidPasswordHashError",
    "PasswordHash",
    "PasswordSecurityError",
    "PasswordService",
]