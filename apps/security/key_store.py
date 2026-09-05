from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from .encryption import (
    EncryptionError,
    EncryptionService,
    InvalidVaultError,
)


# ============================================================================
# EXCEPTIONS
# ============================================================================


class KeyStoreError(Exception):
    """Base exception for filesystem-backed KeyStore failures."""


class VaultAlreadyExistsError(KeyStoreError, FileExistsError):
    """Raised when attempting to create an existing vault."""


class VaultNotFoundError(KeyStoreError, FileNotFoundError):
    """Raised when attempting to access a missing vault."""


# ============================================================================
# KEY STORE
# ============================================================================


class KeyStore:
    """
    Filesystem-backed encrypted wallet vault.

    Responsibilities
    ----------------
    KeyStore owns:

    - vault location
    - filesystem persistence
    - atomic writes
    - vault lifecycle
    - delegation to EncryptionService

    KeyStore does NOT implement cryptography.

    Vault layout:

        <storage_path>/
            vault.enc

    The vault file contains encrypted data only.
    """

    VAULT_FILENAME = "vault.enc"

    # ========================================================================
    # INITIALIZATION
    # ========================================================================

    def __init__(
        self,
        storage_path: str | Path,
        *,
        encryption: EncryptionService | None = None,
    ) -> None:
        """
        Initialize the encrypted vault store.

        Args:
            storage_path:
                Directory in which vault.enc will be stored.

            encryption:
                Optional EncryptionService instance for dependency
                injection and testing.
        """

        if not isinstance(storage_path, (str, Path)):
            raise TypeError(
                "storage_path must be a string or pathlib.Path."
            )

        self.storage_path = Path(storage_path)

        self.storage_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.vault_path = (
            self.storage_path / self.VAULT_FILENAME
        )

        # Backwards-compatible alias.
        self.path = self.vault_path

        self.encryption = (
            encryption
            if encryption is not None
            else EncryptionService()
        )

    # ========================================================================
    # STATUS
    # ========================================================================

    def exists(self) -> bool:
        """Return True if the vault exists as a regular file."""

        return self.vault_path.is_file()

    # ========================================================================
    # CREATE
    # ========================================================================

    def create(
        self,
        secret: bytes,
        password: str,
        *,
        associated_data: bytes | str | None = None,
    ) -> None:
        """
        Create a new encrypted vault.

        Existing vaults are never overwritten.

        Raises:
            TypeError:
                Secret is not bytes.

            ValueError:
                Secret is empty.

            FileExistsError:
                Vault already exists.
        """

        self._validate_secret(secret)

        if self.exists():
            raise FileExistsError(
                f"Vault already exists: {self.vault_path}"
            )

        payload = self._encrypt(
            secret=secret,
            password=password,
            associated_data=associated_data,
        )

        self._atomic_create(payload)

    # ========================================================================
    # SAVE
    # ========================================================================

    def save(
        self,
        secret: bytes,
        password: str,
        *,
        associated_data: bytes | str | None = None,
    ) -> None:
        """
        Create or replace an encrypted vault.

        Replacement is atomic.
        """

        self._validate_secret(secret)

        payload = self._encrypt(
            secret=secret,
            password=password,
            associated_data=associated_data,
        )

        self._atomic_replace(payload)

    # ========================================================================
    # READ
    # ========================================================================

    def read(self) -> bytes:
        """
        Return the encrypted vault payload.

        The payload is never decrypted by this method.

        Raises:
            FileNotFoundError:
                Vault does not exist.

            InvalidVaultError:
                Vault is empty.

            KeyStoreError:
                Filesystem read failure.
        """

        self._require_vault()

        try:
            payload = self.vault_path.read_bytes()

        except FileNotFoundError:
            raise

        except OSError as exc:
            raise KeyStoreError(
                "Unable to read vault."
            ) from exc

        if not payload:
            raise InvalidVaultError(
                "Vault payload cannot be empty."
            )

        return payload

    # ========================================================================
    # OPEN
    # ========================================================================

    def open(
        self,
        password: str,
        *,
        associated_data: bytes | str | None = None,
    ) -> bytes:
        """
        Decrypt and return the wallet secret.

        Authentication errors from EncryptionService are deliberately
        propagated unchanged.
        """

        payload = self.read()

        return self.encryption.decrypt_from_bytes(
            payload,
            password,
            associated_data=self._normalize_associated_data(
                associated_data,
            ),
        )

    # ========================================================================
    # UNLOCK
    # ========================================================================

    def unlock(
        self,
        password: str,
        *,
        associated_data: bytes | str | None = None,
    ) -> bytes:
        """Alias for open()."""

        return self.open(
            password=password,
            associated_data=associated_data,
        )

    # ========================================================================
    # DELETE
    # ========================================================================

    def delete(self) -> None:
        """
        Delete the encrypted vault.

        Deleting a missing vault is considered successful.
        """

        try:
            self.vault_path.unlink(
                missing_ok=True,
            )

        except OSError as exc:
            raise KeyStoreError(
                "Unable to delete vault."
            ) from exc

    # ========================================================================
    # VALIDATE
    # ========================================================================

    def validate(
        self,
        *,
        password: str | None = None,
        associated_data: bytes | str | None = None,
    ) -> bool:
        """
        Validate the vault.

        Returns:
            True:
                Vault is structurally valid and, when a password is
                supplied, successfully authenticated.

            False:
                Vault is missing, corrupted, malformed, or invalid.

        Filesystem failures other than a missing vault are reported
        as KeyStoreError.
        """

        try:
            payload = self.read()

            # Validate the encrypted document without decrypting it.
            self.encryption.deserialize(payload)

            # Optional authenticated validation.
            if password is not None:
                self.open(
                    password=password,
                    associated_data=associated_data,
                )

            return True

        except FileNotFoundError:
            return False

        except (
            EncryptionError,
            InvalidVaultError,
            ValueError,
            TypeError,
        ):
            return False

    # ========================================================================
    # METADATA
    # ========================================================================

    def metadata(self) -> dict[str, Any]:
        """
        Return safe vault metadata.

        Never exposes:

        - plaintext secret
        - password
        - ciphertext
        - salt
        - nonce
        """

        payload = self.read()

        document = self._load_document(payload)

        self._validate_document_structure(
            document,
        )

        kdf = document["kdf"]
        encryption = document["encryption"]

        return {
            "format": document["format"],
            "version": document["version"],
            "algorithm": encryption["algorithm"],
            "kdf": kdf["name"],
            "kdf_parameters": {
                "n": kdf.get("n"),
                "r": kdf.get("r"),
                "p": kdf.get("p"),
                "key_size": kdf.get("key_size"),
                "salt_size": getattr(
                    self.encryption,
                    "SALT_SIZE",
                    None,
                ),
                "nonce_size": getattr(
                    self.encryption,
                    "NONCE_SIZE",
                    None,
                ),
            },
        }

    # ========================================================================
    # ENCRYPTION
    # ========================================================================

    def _encrypt(
        self,
        *,
        secret: bytes,
        password: str,
        associated_data: bytes | str | None = None,
    ) -> bytes:
        """
        Delegate encryption completely to EncryptionService.
        """

        self._validate_secret(secret)

        payload = self.encryption.encrypt_to_bytes(
            secret,
            password,
            associated_data=self._normalize_associated_data(
                associated_data,
            ),
        )

        self._validate_payload(payload)

        return payload

    # ========================================================================
    # ATOMIC CREATE
    # ========================================================================

    def _atomic_create(
        self,
        payload: bytes,
    ) -> None:
        """
        Atomically create a new vault.

        Existing vaults are never replaced.
        """

        self._validate_payload(payload)

        temp_path = self._temporary_path()

        try:
            self._write_and_sync(
                temp_path,
                payload,
            )

            try:
                # Hard-link creation gives us create-if-absent semantics.
                os.link(
                    temp_path,
                    self.vault_path,
                )

            except FileExistsError as exc:
                raise FileExistsError(
                    f"Vault already exists: {self.vault_path}"
                ) from exc

        except FileExistsError:
            raise

        except OSError as exc:
            raise KeyStoreError(
                "Unable to create vault."
            ) from exc

        finally:
            self._cleanup_temp(
                temp_path,
            )

    # ========================================================================
    # ATOMIC REPLACE
    # ========================================================================

    def _atomic_replace(
        self,
        payload: bytes,
    ) -> None:
        """
        Atomically replace the existing vault.
        """

        self._validate_payload(payload)

        temp_path = self._temporary_path()

        try:
            self._write_and_sync(
                temp_path,
                payload,
            )

            os.replace(
                temp_path,
                self.vault_path,
            )

        except OSError as exc:
            raise KeyStoreError(
                "Unable to replace vault."
            ) from exc

        finally:
            self._cleanup_temp(
                temp_path,
            )

    # ========================================================================
    # FILESYSTEM HELPERS
    # ========================================================================

    def _write_and_sync(
        self,
        path: Path,
        payload: bytes,
    ) -> None:
        """
        Write payload and flush it to disk.
        """

        with path.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(
                handle.fileno(),
            )

    def _temporary_path(self) -> Path:
        """
        Generate a unique temporary path.

        Using a unique name prevents concurrent KeyStore instances
        from sharing the same temporary file.
        """

        token = uuid.uuid4().hex

        return self.vault_path.with_name(
            f".{self.vault_path.name}.{token}.tmp"
        )

    @staticmethod
    def _cleanup_temp(
        path: Path,
    ) -> None:
        """Best-effort removal of a temporary file."""

        try:
            path.unlink(
                missing_ok=True,
            )
        except OSError:
            pass

    # ========================================================================
    # DOCUMENT HELPERS
    # ========================================================================

    @staticmethod
    def _load_document(
        payload: bytes,
    ) -> dict[str, Any]:
        """
        Decode the serialized encrypted vault document.
        """

        if not isinstance(payload, bytes):
            raise InvalidVaultError(
                "Vault payload must be bytes."
            )

        if not payload:
            raise InvalidVaultError(
                "Vault payload cannot be empty."
            )

        try:
            document = json.loads(
                payload.decode("utf-8"),
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise InvalidVaultError(
                "Vault payload is not valid JSON."
            ) from exc

        if not isinstance(document, dict):
            raise InvalidVaultError(
                "Vault root must be an object."
            )

        return document

    def _validate_document_structure(
        self,
        document: dict[str, Any],
    ) -> None:
        """
        Validate non-secret vault metadata.
        """

        expected_format = getattr(
            self.encryption,
            "FORMAT",
            None,
        )

        expected_version = getattr(
            self.encryption,
            "VERSION",
            None,
        )

        if document.get("format") != expected_format:
            raise InvalidVaultError(
                "Unsupported vault format."
            )

        if document.get("version") != expected_version:
            raise InvalidVaultError(
                "Unsupported vault version."
            )

        kdf = document.get("kdf")

        if not isinstance(kdf, dict):
            raise InvalidVaultError(
                "Invalid vault KDF configuration."
            )

        encryption = document.get("encryption")

        if not isinstance(encryption, dict):
            raise InvalidVaultError(
                "Invalid vault encryption configuration."
            )

        expected_kdf = getattr(
            self.encryption,
            "KDF",
            None,
        )

        expected_algorithm = getattr(
            self.encryption,
            "ALGORITHM",
            None,
        )

        if kdf.get("name") != expected_kdf:
            raise InvalidVaultError(
                "Unsupported vault KDF."
            )

        if encryption.get("algorithm") != expected_algorithm:
            raise InvalidVaultError(
                "Unsupported vault encryption algorithm."
            )

    # ========================================================================
    # VALIDATION HELPERS
    # ========================================================================

    def _require_vault(self) -> None:
        """
        Require the vault to exist.
        """

        if not self.vault_path.is_file():
            raise FileNotFoundError(
                f"Vault does not exist: {self.vault_path}"
            )

    @staticmethod
    def _validate_payload(
        payload: bytes,
    ) -> None:
        """Validate serialized encrypted data."""

        if not isinstance(payload, bytes):
            raise TypeError(
                "Vault payload must be bytes."
            )

        if not payload:
            raise ValueError(
                "Vault payload cannot be empty."
            )

    @staticmethod
    def _validate_secret(
        secret: bytes,
    ) -> None:
        """Validate raw wallet secret material."""

        if not isinstance(secret, bytes):
            raise TypeError(
                "secret must be bytes."
            )

        if not secret:
            raise ValueError(
                "secret cannot be empty."
            )

    @staticmethod
    def _normalize_associated_data(
        associated_data: bytes | str | None,
    ) -> bytes | None:
        """
        Normalize associated data for AES-GCM.
        """

        if associated_data is None:
            return None

        if isinstance(
            associated_data,
            bytes,
        ):
            return associated_data

        if isinstance(
            associated_data,
            str,
        ):
            return associated_data.encode(
                "utf-8",
            )

        raise TypeError(
            "associated_data must be bytes, str, or None."
        )


__all__ = [
    "KeyStore",
    "KeyStoreError",
    "VaultAlreadyExistsError",
    "VaultNotFoundError",
]