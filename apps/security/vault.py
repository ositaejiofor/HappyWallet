"""
HappyWallet Secure Wallet Vault.

Application-level boundary for encrypted wallet secret material.

Security architecture
---------------------

    WalletSecret
         │
         ▼
    VaultService
         │
         ▼
    EncryptionService
         │
         ▼
    Scrypt + AES-256-GCM


This module is intentionally independent of:

    - Django models
    - HTTP requests
    - sessions
    - templates
    - blockchain RPC
    - blockchain providers
    - databases
    - transaction signing
    - transaction broadcasting

Plaintext wallet secrets are treated as highly sensitive in-memory
material and should exist for the shortest practical lifetime.

IMPORTANT
---------

Never:

    - log WalletSecret
    - serialize WalletSecret for an API response
    - persist WalletSecret directly
    - persist plaintext vault data
    - put wallet secrets into Django sessions
    - put wallet secrets into URLs
    - expose decrypted secrets to frontend JavaScript
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

from .encryption import (
    EncryptionService,
    InvalidPasswordError,
    InvalidVaultError,
)


# ============================================================================
# EXCEPTIONS
# ============================================================================


class VaultError(Exception):
    """Base exception for all wallet-vault errors."""


class VaultSecretError(VaultError):
    """Raised when wallet secret material is invalid."""


class VaultFormatError(VaultError):
    """Raised when wallet-vault content has an invalid structure."""


# ============================================================================
# WALLET SECRET
# ============================================================================


@dataclass(frozen=True, slots=True)
class WalletSecret:
    """
    Sensitive wallet material temporarily held in memory.

    Supported secret material:

        mnemonic
        private_key
        seed

    At least one supported field must be supplied.

    Security notes
    --------------

    This object contains plaintext secret material.

    Callers must:

        - never log it
        - never expose it through HTTP
        - never return it from an API
        - never persist it directly
        - encrypt it before persistence
        - keep its lifetime as short as practical

    This class deliberately performs structural validation only.
    It does not attempt to validate whether a mnemonic, private key,
    or seed is cryptographically valid for a particular blockchain.
    """

    mnemonic: str | None = None
    private_key: str | None = None
    seed: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def validate(self) -> None:
        """
        Validate the structure of the wallet secret.

        Raises:
            VaultSecretError:
                If no secret material is supplied or a supplied field
                has an invalid type/value.
        """

        fields = (
            ("mnemonic", self.mnemonic),
            ("private_key", self.private_key),
            ("seed", self.seed),
        )

        has_secret = False

        for field_name, value in fields:
            if value is None:
                continue

            if not isinstance(value, str):
                raise VaultSecretError(
                    f"{field_name} must be a string or None."
                )

            if not value.strip():
                raise VaultSecretError(
                    f"{field_name} cannot be empty."
                )

            has_secret = True

        if not has_secret:
            raise VaultSecretError(
                "Wallet secret cannot be empty."
            )

    # ------------------------------------------------------------------------
    # SERIALIZATION
    # ------------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Serialize this wallet secret immediately before encryption.

        WARNING:
            The returned bytes contain plaintext secret material.

        The caller is responsible for ensuring the resulting bytes are:

            - encrypted immediately
            - never logged
            - never returned to an untrusted caller
            - never persisted unencrypted
        """

        self.validate()

        payload = {
            "mnemonic": self.mnemonic,
            "private_key": self.private_key,
            "seed": self.seed,
        }

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
    ) -> WalletSecret:
        """
        Reconstruct a WalletSecret from decrypted plaintext bytes.

        The returned object contains plaintext wallet material.

        Raises:
            TypeError:
                If payload is not bytes.

            VaultFormatError:
                If the payload cannot be decoded or has an unsupported
                structure.
        """

        if not isinstance(payload, bytes):
            raise TypeError(
                "Wallet secret payload must be bytes."
            )

        if not payload:
            raise VaultFormatError(
                "Wallet secret payload cannot be empty."
            )

        document = cls._decode_payload(payload)

        cls._validate_document_fields(document)

        try:
            return cls(
                mnemonic=document.get("mnemonic"),
                private_key=document.get("private_key"),
                seed=document.get("seed"),
            )
        except VaultSecretError as exc:
            raise VaultFormatError(
                "Decrypted wallet secret is invalid."
            ) from exc

    @staticmethod
    def _decode_payload(payload: bytes) -> dict[str, object]:
        """
        Decode serialized wallet-secret data.

        This method deliberately returns a generic dictionary first so
        structure can be validated before constructing WalletSecret.
        """

        try:
            decoded = payload.decode("utf-8")
            document = json.loads(decoded)

        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError(
                "Decrypted wallet secret is invalid."
            ) from exc

        if not isinstance(document, dict):
            raise VaultFormatError(
                "Decrypted wallet secret must be an object."
            )

        return document

    @staticmethod
    def _validate_document_fields(
        document: dict[str, object],
    ) -> None:
        """Reject fields that are not part of the wallet-secret schema."""

        allowed_fields = frozenset(
            {
                "mnemonic",
                "private_key",
                "seed",
            }
        )

        unexpected_fields = set(document) - allowed_fields

        if unexpected_fields:
            raise VaultFormatError(
                "Decrypted wallet secret contains unsupported fields."
            )


# ============================================================================
# VAULT SERVICE
# ============================================================================


class VaultService:
    """
    Application-level encrypted wallet vault service.

    Responsibilities
    ----------------

    This service:

        - encrypts WalletSecret objects
        - decrypts encrypted wallet vaults
        - validates encrypted vault structure
        - authenticates vault metadata through AES-GCM associated data

    This service does NOT:

        - access Django models
        - access the database
        - handle HTTP requests
        - manage sessions
        - access blockchain RPC
        - create transactions
        - sign transactions
        - broadcast transactions
        - generate wallet keys
        - derive addresses

    Cryptographic operations are delegated to EncryptionService.
    """

    FORMAT: Final[str] = "happywallet-wallet-vault"
    VERSION: Final[int] = 1

    _ENCODING: Final[str] = "utf-8"

    def __init__(
        self,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        """
        Initialize the vault service.

        Args:
            encryption_service:
                Optional EncryptionService instance.

                Dependency injection is useful for deterministic tests
                and controlled cryptographic configuration.
        """

        self.encryption = (
            encryption_service
            if encryption_service is not None
            else EncryptionService()
        )

    # ========================================================================
    # CREATE
    # ========================================================================

    def create_vault(
        self,
        secret: WalletSecret,
        password: str,
    ) -> bytes:
        """
        Encrypt wallet secret material into an encrypted vault.

        Args:
            secret:
                WalletSecret containing plaintext wallet material.

            password:
                Password used by EncryptionService for key derivation.

        Returns:
            Encrypted vault bytes.

        Raises:
            TypeError:
                If secret or password has the wrong type.

            VaultSecretError:
                If the wallet secret is invalid.

            ValueError:
                If the encryption service rejects the password.

        The returned bytes contain no plaintext wallet secret.
        """

        self._validate_secret(secret)
        self._validate_password(password)

        plaintext = secret.to_bytes()

        try:
            return self.encryption.encrypt_to_bytes(
                plaintext,
                password,
                associated_data=self._associated_data(),
            )
        finally:
            # Remove our reference as soon as encryption completes.
            #
            # Python cannot guarantee zeroization of immutable bytes,
            # but releasing the reference promptly reduces lifetime.
            del plaintext

    # ========================================================================
    # OPEN
    # ========================================================================

    def open_vault(
        self,
        payload: bytes,
        password: str,
    ) -> WalletSecret:
        """
        Decrypt an encrypted wallet vault.

        Args:
            payload:
                Encrypted vault bytes.

            password:
                Wallet password.

        Returns:
            WalletSecret containing decrypted plaintext material.

        Raises:
            TypeError:
                If payload or password has the wrong type.

            VaultFormatError:
                If the encrypted payload is structurally invalid.

            InvalidPasswordError:
                If authentication/password verification fails.

            InvalidVaultError:
                If the encrypted vault cannot be authenticated or
                is otherwise rejected by EncryptionService.

            VaultFormatError:
                If authenticated plaintext does not contain a valid
                wallet-secret structure.

        IMPORTANT:
            The returned WalletSecret contains plaintext secrets.
            Callers must keep its lifetime as short as practical.
        """

        self._validate_payload(payload)
        self._validate_password(password)

        plaintext = self.encryption.decrypt_from_bytes(
            payload,
            password,
            associated_data=self._associated_data(),
        )

        try:
            return WalletSecret.from_bytes(plaintext)
        finally:
            del plaintext

    # ========================================================================
    # VALIDATE
    # ========================================================================

    def validate_vault(
        self,
        payload: bytes,
    ) -> None:
        """
        Validate the encrypted vault envelope without decrypting it.

        This checks that the encrypted payload can be parsed by the
        underlying EncryptionService.

        It does NOT:

            - verify a password
            - decrypt wallet secrets
            - validate mnemonic/private-key contents
            - prove that the vault belongs to a particular wallet

        A successful call means only that the encrypted envelope is
        structurally acceptable to EncryptionService.
        """

        self._validate_payload(payload)

        try:
            self.encryption.deserialize(payload)
        except InvalidVaultError:
            raise

    # ========================================================================
    # INTERNAL VALIDATION
    # ========================================================================

    @staticmethod
    def _validate_secret(
        secret: WalletSecret,
    ) -> None:
        """Validate the WalletSecret object supplied by the caller."""

        if not isinstance(secret, WalletSecret):
            raise TypeError(
                "secret must be a WalletSecret."
            )

        secret.validate()

    @staticmethod
    def _validate_password(
        password: str,
    ) -> None:
        """
        Validate password input before passing it to the crypto layer.

        Password policy itself remains the responsibility of the
        password-policy/security layer.
        """

        if not isinstance(password, str):
            raise TypeError(
                "password must be a string."
            )

        if not password:
            raise ValueError(
                "password cannot be empty."
            )

    @staticmethod
    def _validate_payload(
        payload: bytes,
    ) -> None:
        """Validate the basic encrypted-vault payload type."""

        if not isinstance(payload, bytes):
            raise TypeError(
                "Vault payload must be bytes."
            )

        if not payload:
            raise VaultFormatError(
                "Vault payload cannot be empty."
            )

    # ========================================================================
    # ASSOCIATED DATA
    # ========================================================================

    @classmethod
    def _associated_data(cls) -> bytes:
        """
        Build authenticated non-secret vault metadata.

        AES-256-GCM authenticates this metadata as associated data.

        The metadata itself is not secret.

        Changing FORMAT or VERSION intentionally invalidates existing
        vaults because the associated-data authentication will fail.
        """

        value = f"{cls.FORMAT}:{cls.VERSION}"

        return value.encode(cls._ENCODING)


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "VaultError",
    "VaultSecretError",
    "VaultFormatError",
    "WalletSecret",
    "VaultService",
    "InvalidPasswordError",
    "InvalidVaultError",
]
