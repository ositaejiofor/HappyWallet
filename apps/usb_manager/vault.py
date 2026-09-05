"""HappyWallet USB wallet vault service."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apps.security.encryption import (
    EncryptionService,
    InvalidVaultError,
    VaultDecryptionError,
)
from apps.security.key_store import (
    KeyStore,
    KeyStoreError,
    VaultAlreadyExistsError as KeyStoreVaultAlreadyExistsError,
    VaultNotFoundError as KeyStoreVaultNotFoundError,
)
from apps.security.vault import (
    WalletSecret,
    VaultFormatError,
    VaultSecretError,
)

from .detector import USBDevice, USBDetector


# ============================================================================
# EXCEPTIONS
# ============================================================================


class USBVaultError(Exception):
    """Base exception for USB vault errors."""


class VaultNotFoundError(USBVaultError):
    """Raised when the wallet vault does not exist."""


class VaultAlreadyExistsError(USBVaultError):
    """Raised when a wallet vault already exists."""


class InvalidUSBVaultError(USBVaultError):
    """Raised when vault metadata or structure is invalid."""


# ============================================================================
# METADATA
# ============================================================================


@dataclass(frozen=True, slots=True)
class VaultMetadata:
    """Public, non-secret information describing a wallet vault."""

    vault_id: str
    wallet_name: str
    version: int
    created_at: str
    network: str
    device_type: str = "usb-cold-wallet"

    def __post_init__(self) -> None:
        """Validate vault metadata."""

        if not isinstance(self.vault_id, str) or not self.vault_id.strip():
            raise InvalidUSBVaultError(
                "Vault ID cannot be empty."
            )

        if (
            not isinstance(self.wallet_name, str)
            or not self.wallet_name.strip()
        ):
            raise InvalidUSBVaultError(
                "Wallet name cannot be empty."
            )

        if not isinstance(self.version, int) or self.version < 1:
            raise InvalidUSBVaultError(
                "Vault version must be positive."
            )

        if (
            not isinstance(self.created_at, str)
            or not self.created_at.strip()
        ):
            raise InvalidUSBVaultError(
                "Vault creation timestamp cannot be empty."
            )

        if not isinstance(self.network, str) or not self.network.strip():
            raise InvalidUSBVaultError(
                "Vault network cannot be empty."
            )

        if (
            not isinstance(self.device_type, str)
            or not self.device_type.strip()
        ):
            raise InvalidUSBVaultError(
                "Vault device type cannot be empty."
            )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-safe public metadata."""

        return {
            "vault_id": self.vault_id,
            "wallet_name": self.wallet_name,
            "version": self.version,
            "created_at": self.created_at,
            "network": self.network,
            "device_type": self.device_type,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "VaultMetadata":
        """Create metadata from a JSON object."""

        if not isinstance(data, dict):
            raise InvalidUSBVaultError(
                "Vault metadata must be an object."
            )

        required_fields = (
            "vault_id",
            "wallet_name",
            "version",
            "created_at",
            "network",
        )

        for field in required_fields:
            if field not in data:
                raise InvalidUSBVaultError(
                    f"Missing vault metadata field: {field}"
                )

        try:
            return cls(
                vault_id=str(data["vault_id"]),
                wallet_name=str(data["wallet_name"]),
                version=int(data["version"]),
                created_at=str(data["created_at"]),
                network=str(data["network"]),
                device_type=str(
                    data.get(
                        "device_type",
                        "usb-cold-wallet",
                    )
                ),
            )

        except (TypeError, ValueError) as exc:
            raise InvalidUSBVaultError(
                "Vault metadata is invalid."
            ) from exc


# ============================================================================
# USB VAULT
# ============================================================================


class USBVault:
    """Manage an encrypted HappyWallet vault stored on USB media."""

    VAULT_VERSION = 1

    VAULT_DIRECTORY = "HappyWallet"

    # This is the KeyStore directory name.
    VAULT_FILENAME = "wallet.vault"

    # KeyStore stores the actual encrypted payload inside VAULT_FILENAME.
    KEYSTORE_FILENAME = "vault.enc"

    METADATA_FILENAME = "vault.json"
    METADATA_TEMP_FILENAME = ".vault.json.tmp"

    def __init__(
        self,
        device: USBDevice,
        encryption: EncryptionService | None = None,
    ) -> None:
        """Initialize the USB vault manager."""

        if not isinstance(device, USBDevice):
            raise TypeError(
                "device must be a USBDevice."
            )

        self.device = device
        self.detector = USBDetector()

        self.encryption = (
            encryption
            if encryption is not None
            else EncryptionService()
        )

        # USB root:
        #
        #   <mount>/HappyWallet/
        #
        self.root = (
            self.device.mount_path
            / self.VAULT_DIRECTORY
        )

        # KeyStore directory:
        #
        #   <mount>/HappyWallet/wallet.vault/
        #
        self.vault_dir = (
            self.root
            / self.VAULT_FILENAME
        )

        # Actual encrypted payload:
        #
        #   <mount>/HappyWallet/wallet.vault/vault.enc
        #
        self.vault_path = (
            self.vault_dir
            / self.KEYSTORE_FILENAME
        )

        # Public metadata:
        #
        #   <mount>/HappyWallet/vault.json
        #
        self.metadata_path = (
            self.root
            / self.METADATA_FILENAME
        )

    # ========================================================================
    # DEVICE
    # ========================================================================

    def is_available(self) -> bool:
        """Return True when the USB device is available."""

        try:
            return self.detector.is_available(
                self.device
            )
        except (OSError, RuntimeError):
            return False

    def require_available(self) -> None:
        """Require the USB device to be available."""

        if not self.is_available():
            raise USBVaultError(
                "USB device is no longer available."
            )

    # ========================================================================
    # VAULT STATE
    # ========================================================================

    def exists(self) -> bool:
        """
        Return True only when the vault is complete.

        A complete vault contains:

            - encrypted payload
            - public metadata
        """

        return (
            self.vault_path.is_file()
            and self.metadata_path.is_file()
        )

    def _has_existing_data(self) -> bool:
        """
        Return True when vault data already exists.

        A partial vault must never be silently overwritten.
        """

        return (
            self.vault_path.exists()
            or self.metadata_path.exists()
        )

    # ========================================================================
    # CREATE
    # ========================================================================

    def create(
        self,
        secret: WalletSecret,
        password: str,
        *,
        wallet_name: str = "HappyWallet",
        network: str = "ethereum",
    ) -> VaultMetadata:
        """Create a new encrypted wallet vault."""

        self.require_available()

        # --------------------------------------------------------------
        # SECRET
        # --------------------------------------------------------------

        if not isinstance(secret, WalletSecret):
            raise TypeError(
                "secret must be a WalletSecret."
            )

        secret.validate()

        # --------------------------------------------------------------
        # PASSWORD
        # --------------------------------------------------------------

        self.encryption.validate_password(
            password
        )

        # --------------------------------------------------------------
        # WALLET NAME
        # --------------------------------------------------------------

        if not isinstance(wallet_name, str):
            raise TypeError(
                "wallet_name must be a string."
            )

        wallet_name = wallet_name.strip()

        if not wallet_name:
            raise ValueError(
                "Wallet name cannot be empty."
            )

        # --------------------------------------------------------------
        # NETWORK
        # --------------------------------------------------------------

        if not isinstance(network, str):
            raise TypeError(
                "network must be a string."
            )

        network = network.strip().lower()

        if not network:
            raise ValueError(
                "Network cannot be empty."
            )

        # --------------------------------------------------------------
        # EXISTING VAULT
        # --------------------------------------------------------------

        if self._has_existing_data():
            raise VaultAlreadyExistsError(
                "A HappyWallet vault already exists on this USB device."
            )

        # --------------------------------------------------------------
        # CREATE ROOT DIRECTORY
        # --------------------------------------------------------------

        try:
            self.root.mkdir(
                parents=True,
                exist_ok=True,
            )
        except OSError as exc:
            raise USBVaultError(
                "Unable to create USB vault directory."
            ) from exc

        # --------------------------------------------------------------
        # METADATA
        # --------------------------------------------------------------

        metadata = VaultMetadata(
            vault_id=secrets.token_hex(16),
            wallet_name=wallet_name,
            version=self.VAULT_VERSION,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            network=network,
        )

        associated_data = self._associated_data(
            metadata
        )

        # --------------------------------------------------------------
        # SERIALIZE SECRET
        # --------------------------------------------------------------

        plaintext = secret.to_bytes()
        store = self._store()

        try:
            store.create(
                secret=plaintext,
                password=password,
                associated_data=associated_data,
            )

        except (
            KeyStoreVaultAlreadyExistsError,
            FileExistsError,
        ) as exc:
            raise VaultAlreadyExistsError(
                "A HappyWallet vault already exists on this USB device."
            ) from exc

        except KeyStoreError as exc:
            raise USBVaultError(
                "Unable to create encrypted USB vault."
            ) from exc

        finally:
            del plaintext

        # --------------------------------------------------------------
        # WRITE METADATA
        # --------------------------------------------------------------

        try:
            self._write_metadata(
                metadata
            )

        except Exception:
            # Roll back the encrypted payload if metadata
            # creation fails.
            try:
                store.delete()
            except (
                KeyStoreError,
                OSError,
            ):
                pass

            # Remove the empty KeyStore directory when possible.
            try:
                if self.vault_dir.exists():
                    self.vault_dir.rmdir()
            except OSError:
                pass

            raise

        return metadata

    # ========================================================================
    # UNLOCK
    # ========================================================================

    def unlock(
        self,
        password: str,
    ) -> WalletSecret:
        """Decrypt and return the wallet secret."""

        self.require_available()

        # The actual encrypted payload is:
        #
        #   wallet.vault/vault.enc
        #
        if not self.vault_path.is_file():
            raise VaultNotFoundError(
                "Wallet vault file does not exist."
            )

        if not self.metadata_path.is_file():
            raise VaultNotFoundError(
                "Wallet vault metadata does not exist."
            )

        metadata = self.read_metadata()

        store = self._store()

        # --------------------------------------------------------------
        # DECRYPT
        # --------------------------------------------------------------

        try:
            plaintext = store.unlock(
                password=password,
                associated_data=self._associated_data(
                    metadata
                ),
            )

        except KeyStoreVaultNotFoundError as exc:
            raise VaultNotFoundError(
                "Wallet vault file does not exist."
            ) from exc

        except (
            VaultDecryptionError,
            InvalidVaultError,
        ):
            # Preserve the cryptographic failure so callers/tests
            # can distinguish incorrect passwords or tampering.
            raise

        except KeyStoreError as exc:
            raise USBVaultError(
                "Unable to unlock USB wallet vault."
            ) from exc

        # --------------------------------------------------------------
        # DESERIALIZE
        # --------------------------------------------------------------

        try:
            return WalletSecret.from_bytes(
                plaintext
            )

        except (
            TypeError,
            ValueError,
            VaultFormatError,
            VaultSecretError,
        ) as exc:
            raise InvalidUSBVaultError(
                "Decrypted USB wallet data is invalid."
            ) from exc

        finally:
            del plaintext

    # ========================================================================
    # PASSWORD
    # ========================================================================

    def verify_password(
        self,
        password: str,
    ) -> bool:
        """Return True when the supplied password unlocks the vault."""

        try:
            secret = self.unlock(
                password
            )

            del secret

            return True

        except (
            USBVaultError,
            VaultDecryptionError,
            InvalidVaultError,
            InvalidUSBVaultError,
            KeyStoreError,
        ):
            return False

    # ========================================================================
    # METADATA
    # ========================================================================

    def read_metadata(self) -> VaultMetadata:
        """Read and validate public vault metadata."""

        self.require_available()

        if not self.metadata_path.is_file():
            raise VaultNotFoundError(
                "Vault metadata does not exist."
            )

        try:
            raw = self.metadata_path.read_text(
                encoding="utf-8"
            )

        except (
            OSError,
            UnicodeError,
        ) as exc:
            raise InvalidUSBVaultError(
                "Unable to read USB vault metadata."
            ) from exc

        try:
            data = json.loads(
                raw
            )

        except json.JSONDecodeError as exc:
            raise InvalidUSBVaultError(
                "USB vault metadata is not valid JSON."
            ) from exc

        return VaultMetadata.from_dict(
            data
        )

    def _write_metadata(
        self,
        metadata: VaultMetadata,
    ) -> None:
        """Atomically write public vault metadata."""

        if not isinstance(
            metadata,
            VaultMetadata,
        ):
            raise TypeError(
                "metadata must be VaultMetadata."
            )

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = json.dumps(
            metadata.to_dict(),
            indent=2,
            sort_keys=True,
        )

        temp_path = (
            self.root
            / self.METADATA_TEMP_FILENAME
        )

        try:
            temp_path.write_text(
                payload,
                encoding="utf-8",
            )

            temp_path.replace(
                self.metadata_path
            )

        except OSError as exc:
            raise USBVaultError(
                "Unable to write USB vault metadata."
            ) from exc

        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    # ========================================================================
    # ASSOCIATED DATA
    # ========================================================================

    @staticmethod
    def _associated_data(
        metadata: VaultMetadata,
    ) -> bytes:
        """
        Build authenticated associated data for the encrypted vault.

        The encrypted payload is cryptographically bound to:

            - HappyWallet format
            - vault version
            - vault ID
            - blockchain network
        """

        if not isinstance(
            metadata,
            VaultMetadata,
        ):
            raise TypeError(
                "metadata must be VaultMetadata."
            )

        value = (
            "happywallet|"
            f"{metadata.version}|"
            f"{metadata.vault_id}|"
            f"{metadata.network}"
        )

        return value.encode(
            "utf-8"
        )

    # ========================================================================
    # KEY STORE
    # ========================================================================

    def _store(self) -> KeyStore:
        """
        Return the KeyStore responsible for encrypted persistence.

        KeyStore receives the vault directory, not the final vault.enc
        file path.
        """

        return KeyStore(
            self.vault_dir,
            encryption=self.encryption,
        )

    # ========================================================================
    # REMOVE
    # ========================================================================

    def remove_vault(self) -> None:
        """Remove the encrypted vault and public metadata."""

        self.require_available()

        store = self._store()

        try:
            store.delete()

        except KeyStoreVaultNotFoundError:
            pass

        except KeyStoreError as exc:
            raise USBVaultError(
                "Unable to remove wallet vault."
            ) from exc

        # Remove metadata.
        if self.metadata_path.exists():
            try:
                self.metadata_path.unlink()

            except OSError as exc:
                raise USBVaultError(
                    "Unable to remove vault metadata."
                ) from exc

        # Remove empty KeyStore directory.
        try:
            if self.vault_dir.exists():
                self.vault_dir.rmdir()
        except OSError:
            pass

    # ========================================================================
    # INFORMATION
    # ========================================================================

    def information(self) -> dict[str, Any]:
        """Return safe, non-secret information about the vault."""

        self.require_available()

        info: dict[str, Any] = {
            "device_id": self.device.device_id,
            "mount_path": str(
                self.device.mount_path
            ),
            "vault_exists": self.exists(),
        }

        if not self.exists():
            return info

        metadata = self.read_metadata()

        info.update(
            {
                "vault_id": metadata.vault_id,
                "wallet_name": metadata.wallet_name,
                "network": metadata.network,
                "version": metadata.version,
                "created_at": metadata.created_at,
                "device_type": metadata.device_type,
            }
        )

        return info


__all__ = [
    "USBVault",
    "USBVaultError",
    "VaultMetadata",
    "VaultNotFoundError",
    "VaultAlreadyExistsError",
    "InvalidUSBVaultError",
]
