"""
HappyWallet Vault Encryption Service.

Security model
--------------

    Password
        |
        v
    Scrypt KDF
        |
        v
    256-bit encryption key
        |
        v
    AES-256-GCM
        |
        v
    Authenticated encrypted vault

Responsibilities
----------------
This module owns:

    - password-based key derivation
    - authenticated encryption
    - authenticated decryption
    - vault serialization
    - vault deserialization
    - vault-format validation

This module deliberately does NOT know about:

    - Django models
    - HTTP requests
    - sessions
    - templates
    - blockchain RPC
    - wallet business logic
    - filesystem persistence

Security properties
-------------------
    - plaintext secrets are never logged
    - passwords are never persisted
    - every encryption uses a fresh salt
    - every encryption uses a fresh nonce
    - AES-GCM authentication is mandatory
    - malformed vault payloads are rejected
    - unsupported vault versions are rejected
    - cryptographic failures are normalized
    - serialized cryptographic parameters are authenticated by validation
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# ============================================================================
# EXCEPTIONS
# ============================================================================


class EncryptionError(Exception):
    """Base exception for HappyWallet encryption failures."""


class VaultDecryptionError(EncryptionError):
    """Base exception for vault decryption failures."""


class InvalidPasswordError(VaultDecryptionError):
    """
    Raised when authenticated decryption fails.

    The exception deliberately does not distinguish between:

        - wrong password
        - modified ciphertext
        - modified nonce
        - modified associated data

    This prevents unnecessary information disclosure.
    """


class InvalidVaultError(EncryptionError):
    """
    Raised when a serialized vault is malformed, corrupted,
    unsupported, or otherwise unsafe to process.
    """


# ============================================================================
# ENCRYPTED BLOB
# ============================================================================


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    """
    Immutable AES-256-GCM encrypted payload.

    Attributes
    ----------
    salt:
        Random Scrypt salt.

    nonce:
        Random AES-GCM nonce.

    ciphertext:
        AES-GCM ciphertext including the authentication tag.

    Notes
    -----
    SALT_SIZE and NONCE_SIZE are ClassVars so dataclasses does not
    treat them as instance fields.
    """

    SALT_SIZE: ClassVar[Final[int]] = 16
    NONCE_SIZE: ClassVar[Final[int]] = 12
    AUTH_TAG_SIZE: ClassVar[Final[int]] = 16

    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        self._validate_bytes(self.salt, "salt")
        self._validate_bytes(self.nonce, "nonce")
        self._validate_bytes(self.ciphertext, "ciphertext")

        if len(self.salt) != self.SALT_SIZE:
            raise ValueError(
                f"Salt must be exactly {self.SALT_SIZE} bytes."
            )

        if len(self.nonce) != self.NONCE_SIZE:
            raise ValueError(
                f"Nonce must be exactly {self.NONCE_SIZE} bytes."
            )

        if len(self.ciphertext) < self.AUTH_TAG_SIZE:
            raise ValueError(
                "Ciphertext is too short for AES-GCM."
            )

    # ------------------------------------------------------------------------
    # SERIALIZATION
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, str]:
        """
        Convert the encrypted blob into JSON-safe Base64 strings.

        No plaintext secret material is included.
        """
        return {
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "EncryptedBlob":
        """
        Restore an EncryptedBlob from serialized data.

        Malformed data is normalized into InvalidVaultError.
        """
        if not isinstance(data, dict):
            raise InvalidVaultError(
                "Encrypted blob must be an object."
            )

        required_fields = frozenset(
            {
                "salt",
                "nonce",
                "ciphertext",
            }
        )

        if frozenset(data.keys()) != required_fields:
            raise InvalidVaultError(
                "Invalid encrypted blob fields."
            )

        try:
            salt = cls._decode_base64(data["salt"])
            nonce = cls._decode_base64(data["nonce"])
            ciphertext = cls._decode_base64(data["ciphertext"])

        except (
            TypeError,
            ValueError,
            binascii.Error,
        ) as exc:
            raise InvalidVaultError(
                "Invalid encrypted blob encoding."
            ) from exc

        try:
            return cls(
                salt=salt,
                nonce=nonce,
                ciphertext=ciphertext,
            )

        except (TypeError, ValueError) as exc:
            raise InvalidVaultError(
                "Invalid encrypted blob."
            ) from exc

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    @staticmethod
    def _validate_bytes(
        value: bytes,
        name: str,
    ) -> None:
        """Require an actual bytes value."""
        if not isinstance(value, bytes):
            raise TypeError(
                f"{name} must be bytes."
            )

    @staticmethod
    def _decode_base64(
        value: Any,
    ) -> bytes:
        """
        Strictly decode a Base64 string.
        """
        if not isinstance(value, str):
            raise TypeError(
                "Encrypted blob values must be strings."
            )

        if not value:
            raise ValueError(
                "Encrypted blob values cannot be empty."
            )

        return base64.b64decode(
            value,
            validate=True,
        )


# ============================================================================
# ENCRYPTION SERVICE
# ============================================================================


class EncryptionService:
    """
    Password-based authenticated encryption service.

    Cryptographic design:

        Password
            |
            v
        Scrypt
            |
            v
        256-bit key
            |
            v
        AES-256-GCM
            |
            v
        EncryptedBlob

    The service is independent from filesystem persistence.
    """

    # ========================================================================
    # VAULT FORMAT
    # ========================================================================

    VERSION: Final[int] = 1
    FORMAT: Final[str] = "happywallet-vault"

    # ========================================================================
    # CRYPTOGRAPHIC ALGORITHM
    # ========================================================================

    ALGORITHM: Final[str] = "AES-256-GCM"
    KDF: Final[str] = "scrypt"

    # ========================================================================
    # CRYPTOGRAPHIC SIZES
    # ========================================================================

    SALT_SIZE: Final[int] = 16
    NONCE_SIZE: Final[int] = 12
    KEY_SIZE: Final[int] = 32

    # ========================================================================
    # SCRYPT PARAMETERS
    # ========================================================================

    SCRYPT_N: Final[int] = 2**15
    SCRYPT_R: Final[int] = 8
    SCRYPT_P: Final[int] = 1

    # ========================================================================
    # PASSWORD POLICY
    # ========================================================================

    MIN_PASSWORD_LENGTH: Final[int] = 12

    # ========================================================================
    # SERIALIZED FIELD CONTRACT
    # ========================================================================

    _ROOT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "format",
            "version",
            "kdf",
            "encryption",
            "data",
        }
    )

    _KDF_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "name",
            "n",
            "r",
            "p",
            "key_size",
        }
    )

    _ENCRYPTION_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "algorithm",
        }
    )

    # ========================================================================
    # INITIALIZATION
    # ========================================================================

    def __init__(
        self,
        *,
        n: int | None = None,
        r: int | None = None,
        p: int | None = None,
    ) -> None:
        """
        Initialize the encryption service.

        Optional Scrypt parameters are retained for tests and controlled
        environments.

        Production should use the default parameters unless a deliberate
        migration/versioning strategy exists.
        """
        self.scrypt_n = (
            self.SCRYPT_N
            if n is None
            else n
        )

        self.scrypt_r = (
            self.SCRYPT_R
            if r is None
            else r
        )

        self.scrypt_p = (
            self.SCRYPT_P
            if p is None
            else p
        )

        self._validate_scrypt_parameters()

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
        """
        if not isinstance(password, str):
            raise TypeError(
                "Password must be a string."
            )

        if not password:
            raise ValueError(
                "Password cannot be empty."
            )

        if len(password) < cls.MIN_PASSWORD_LENGTH:
            raise ValueError(
                "Wallet password must contain at least "
                f"{cls.MIN_PASSWORD_LENGTH} characters."
            )

    # ========================================================================
    # SCRYPT VALIDATION
    # ========================================================================

    def _validate_scrypt_parameters(self) -> None:
        """Validate configured Scrypt parameters."""

        if not isinstance(self.scrypt_n, int):
            raise TypeError(
                "Scrypt N parameter must be an integer."
            )

        if self.scrypt_n <= 1:
            raise ValueError(
                "Invalid Scrypt N parameter."
            )

        if self.scrypt_n & (self.scrypt_n - 1):
            raise ValueError(
                "Scrypt N must be a power of two."
            )

        if not isinstance(self.scrypt_r, int):
            raise TypeError(
                "Scrypt r parameter must be an integer."
            )

        if self.scrypt_r <= 0:
            raise ValueError(
                "Invalid Scrypt r parameter."
            )

        if not isinstance(self.scrypt_p, int):
            raise TypeError(
                "Scrypt p parameter must be an integer."
            )

        if self.scrypt_p <= 0:
            raise ValueError(
                "Invalid Scrypt p parameter."
            )

    # ========================================================================
    # KEY DERIVATION
    # ========================================================================

    def derive_key(
        self,
        password: str,
        salt: bytes,
    ) -> bytes:
        """
        Derive a 256-bit encryption key using Scrypt.
        """
        self.validate_password(password)
        self._validate_salt(salt)

        kdf = Scrypt(
            salt=salt,
            length=self.KEY_SIZE,
            n=self.scrypt_n,
            r=self.scrypt_r,
            p=self.scrypt_p,
        )

        return kdf.derive(
            password.encode("utf-8")
        )

    # ========================================================================
    # ENCRYPTION
    # ========================================================================

    def encrypt(
        self,
        plaintext: bytes,
        password: str,
        *,
        associated_data: bytes | None = None,
    ) -> EncryptedBlob:
        """
        Encrypt plaintext using AES-256-GCM.

        Every encryption receives:

            - a fresh random salt
            - a fresh random nonce
        """
        self._validate_plaintext(plaintext)
        self.validate_password(password)
        self._validate_associated_data(associated_data)

        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)

        key = self.derive_key(
            password,
            salt,
        )

        try:
            ciphertext = AESGCM(key).encrypt(
                nonce,
                plaintext,
                associated_data,
            )
        except Exception as exc:
            raise EncryptionError(
                "Unable to encrypt wallet vault."
            ) from exc

        return EncryptedBlob(
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    # ========================================================================
    # DECRYPTION
    # ========================================================================

    def decrypt(
        self,
        blob: EncryptedBlob,
        password: str,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Authenticate and decrypt an encrypted blob.

        Authentication failures are normalized into
        InvalidPasswordError.
        """
        if not isinstance(blob, EncryptedBlob):
            raise TypeError(
                "blob must be an EncryptedBlob."
            )

        self.validate_password(password)
        self._validate_associated_data(associated_data)

        key = self.derive_key(
            password,
            blob.salt,
        )

        try:
            return AESGCM(key).decrypt(
                blob.nonce,
                blob.ciphertext,
                associated_data,
            )

        except InvalidTag as exc:
            raise InvalidPasswordError(
                "Unable to decrypt wallet vault."
            ) from exc

    # ========================================================================
    # SERIALIZATION
    # ========================================================================

    def serialize(
        self,
        blob: EncryptedBlob,
    ) -> bytes:
        """
        Serialize an encrypted blob into the HappyWallet vault format.
        """
        if not isinstance(blob, EncryptedBlob):
            raise TypeError(
                "blob must be an EncryptedBlob."
            )

        document = {
            "format": self.FORMAT,
            "version": self.VERSION,
            "kdf": {
                "name": self.KDF,
                "n": self.scrypt_n,
                "r": self.scrypt_r,
                "p": self.scrypt_p,
                "key_size": self.KEY_SIZE,
            },
            "encryption": {
                "algorithm": self.ALGORITHM,
            },
            "data": blob.to_dict(),
        }

        try:
            return json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")

        except (TypeError, ValueError) as exc:
            raise EncryptionError(
                "Unable to serialize wallet vault."
            ) from exc

    # ========================================================================
    # DESERIALIZATION
    # ========================================================================

    def deserialize(
        self,
        payload: bytes,
    ) -> EncryptedBlob:
        """
        Deserialize and fully validate a vault payload.
        """
        document = self._decode_document(payload)

        self._validate_document(document)

        return EncryptedBlob.from_dict(
            document["data"]
        )

    # ------------------------------------------------------------------------
    # DOCUMENT DECODING
    # ------------------------------------------------------------------------

    @staticmethod
    def _decode_document(
        payload: bytes,
    ) -> dict[str, Any]:
        """
        Decode the serialized vault document.
        """
        if not isinstance(payload, bytes):
            raise TypeError(
                "Vault payload must be bytes."
            )

        if not payload:
            raise InvalidVaultError(
                "Vault payload cannot be empty."
            )

        try:
            document = json.loads(
                payload.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise InvalidVaultError(
                "Vault is not valid JSON."
            ) from exc

        if not isinstance(document, dict):
            raise InvalidVaultError(
                "Vault root must be an object."
            )

        return document

    # ------------------------------------------------------------------------
    # DOCUMENT VALIDATION
    # ------------------------------------------------------------------------

    def _validate_document(
        self,
        document: dict[str, Any],
    ) -> None:
        """
        Validate the complete vault structure.
        """
        if frozenset(document.keys()) != self._ROOT_FIELDS:
            raise InvalidVaultError(
                "Invalid vault document fields."
            )

        if document.get("format") != self.FORMAT:
            raise InvalidVaultError(
                "Unsupported HappyWallet vault format."
            )

        if document.get("version") != self.VERSION:
            raise InvalidVaultError(
                "Unsupported HappyWallet vault version."
            )

        self._validate_kdf_configuration(
            document.get("kdf")
        )

        self._validate_encryption_configuration(
            document.get("encryption")
        )

        if not isinstance(
            document.get("data"),
            dict,
        ):
            raise InvalidVaultError(
                "Invalid encrypted vault data."
            )

    # ------------------------------------------------------------------------
    # KDF VALIDATION
    # ------------------------------------------------------------------------

    def _validate_kdf_configuration(
        self,
        kdf: Any,
    ) -> None:
        """Validate serialized Scrypt configuration."""

        if not isinstance(kdf, dict):
            raise InvalidVaultError(
                "Invalid vault KDF configuration."
            )

        if frozenset(kdf.keys()) != self._KDF_FIELDS:
            raise InvalidVaultError(
                "Invalid vault KDF fields."
            )

        if kdf.get("name") != self.KDF:
            raise InvalidVaultError(
                "Unsupported vault KDF."
            )

        expected = {
            "n": self.scrypt_n,
            "r": self.scrypt_r,
            "p": self.scrypt_p,
            "key_size": self.KEY_SIZE,
        }

        for field, expected_value in expected.items():
            if kdf.get(field) != expected_value:
                raise InvalidVaultError(
                    "Vault KDF parameters do not match."
                )

    # ------------------------------------------------------------------------
    # ENCRYPTION CONFIGURATION VALIDATION
    # ------------------------------------------------------------------------

    def _validate_encryption_configuration(
        self,
        encryption: Any,
    ) -> None:
        """Validate serialized encryption configuration."""

        if not isinstance(encryption, dict):
            raise InvalidVaultError(
                "Invalid vault encryption configuration."
            )

        if frozenset(encryption.keys()) != self._ENCRYPTION_FIELDS:
            raise InvalidVaultError(
                "Invalid vault encryption fields."
            )

        if encryption.get("algorithm") != self.ALGORITHM:
            raise InvalidVaultError(
                "Unsupported vault encryption algorithm."
            )

    # ========================================================================
    # COMPLETE BYTE API
    # ========================================================================

    def encrypt_to_bytes(
        self,
        plaintext: bytes,
        password: str,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Encrypt plaintext and return the complete serialized vault.
        """
        blob = self.encrypt(
            plaintext,
            password,
            associated_data=associated_data,
        )

        return self.serialize(blob)

    def decrypt_from_bytes(
        self,
        payload: bytes,
        password: str,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Deserialize and decrypt a complete vault payload.
        """
        blob = self.deserialize(payload)

        return self.decrypt(
            blob,
            password,
            associated_data=associated_data,
        )

    # ========================================================================
    # VALIDATION HELPERS
    # ========================================================================

    @staticmethod
    def _validate_plaintext(
        plaintext: bytes,
    ) -> None:
        """Validate plaintext before encryption."""
        if not isinstance(plaintext, bytes):
            raise TypeError(
                "Plaintext must be bytes."
            )

        if not plaintext:
            raise ValueError(
                "Plaintext cannot be empty."
            )

    @classmethod
    def _validate_salt(
        cls,
        salt: bytes,
    ) -> None:
        """Validate a Scrypt salt."""
        if not isinstance(salt, bytes):
            raise TypeError(
                "Salt must be bytes."
            )

        if len(salt) != cls.SALT_SIZE:
            raise ValueError(
                f"Salt must be {cls.SALT_SIZE} bytes."
            )

    @staticmethod
    def _validate_associated_data(
        associated_data: bytes | None,
    ) -> None:
        """Validate AES-GCM associated data."""
        if (
            associated_data is not None
            and not isinstance(associated_data, bytes)
        ):
            raise TypeError(
                "Associated data must be bytes or None."
            )


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "EncryptedBlob",
    "EncryptionError",
    "EncryptionService",
    "InvalidPasswordError",
    "InvalidVaultError",
    "VaultDecryptionError",
]
