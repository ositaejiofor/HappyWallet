from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.security.encryption import (
    EncryptionService,
    InvalidPasswordError,
    InvalidVaultError,
)
from apps.security.key_store import KeyStore


class KeyStoreTestCase(SimpleTestCase):
    """Tests for the HappyWallet encrypted key store."""

    def setUp(self) -> None:
        self.storage_path = self.create_temp_directory()

        self.password = "correct horse battery staple"

        self.secret = (
            b"happywallet-sensitive-wallet-material"
        )

        self.store = KeyStore(
            storage_path=self.storage_path,
        )

    def create_temp_directory(self) -> str:
        """Create an isolated temporary directory for each test."""
        return tempfile.mkdtemp(
            prefix="happywallet_keystore_"
        )

    def tearDown(self) -> None:
        """Remove the temporary directory after each test."""
        if hasattr(self, "storage_path"):
            shutil.rmtree(
                self.storage_path,
                ignore_errors=True,
            )

        super().tearDown()

    # ==============================================================
    # INITIAL STATE
    # ==============================================================

    def test_vault_does_not_exist_initially(self) -> None:
        """A new key store should not contain a vault."""

        self.assertFalse(
            self.store.exists()
        )

    def test_vault_uses_expected_file_name(self) -> None:
        """The store should use the expected vault filename."""

        path = Path(self.storage_path)

        expected = path / "vault.enc"

        self.assertEqual(
            self.store.vault_path,
            expected,
        )

    # ==============================================================
    # CREATE
    # ==============================================================

    def test_create_vault(self) -> None:
        """Creating a vault should persist the secret securely."""

        self.store.create(
            self.secret,
            self.password,
        )

        self.assertTrue(
            self.store.exists()
        )

        self.assertEqual(
            self.store.open(self.password),
            self.secret,
        )

    def test_create_does_not_overwrite_existing_vault(self) -> None:
        """Create must not overwrite an existing vault."""

        self.store.create(
            self.secret,
            self.password,
        )

        with self.assertRaises(
            FileExistsError
        ):
            self.store.create(
                b"different-secret",
                self.password,
            )

        self.assertEqual(
            self.store.open(self.password),
            self.secret,
        )

    def test_create_rejects_invalid_secret(self) -> None:
        """Empty or non-byte secrets must be rejected."""

        with self.assertRaises(
            (TypeError, ValueError)
        ):
            self.store.create(
                b"",
                self.password,
            )

    # ==============================================================
    # OPEN
    # ==============================================================

    def test_open_returns_original_secret(self) -> None:
        """Opening a vault should return the original secret."""

        self.store.create(
            self.secret,
            self.password,
        )

        result = self.store.open(
            self.password
        )

        self.assertEqual(
            result,
            self.secret,
        )

    def test_opening_missing_vault_fails(self) -> None:
        """Opening a missing vault must fail."""

        with self.assertRaises(
            FileNotFoundError
        ):
            self.store.open(
                self.password
            )

    def test_wrong_password_is_rejected(self) -> None:
        """An incorrect password must not decrypt the vault."""

        self.store.create(
            self.secret,
            self.password,
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.store.open(
                "wrong password"
            )

    def test_corrupted_vault_cannot_be_opened(self) -> None:
        """Corrupted vault data must not be accepted."""

        self.store.create(
            self.secret,
            self.password,
        )

        self.store.vault_path.write_bytes(
            b"corrupted vault data"
        )

        with self.assertRaises(
            (InvalidVaultError, ValueError)
        ):
            self.store.open(
                self.password
            )

    def test_deleted_vault_cannot_be_opened(self) -> None:
        """A deleted vault cannot be opened."""

        self.store.create(
            self.secret,
            self.password,
        )

        self.store.delete()

        with self.assertRaises(
            FileNotFoundError
        ):
            self.store.open(
                self.password
            )

    # ==============================================================
    # READ
    # ==============================================================

    def test_read_returns_encrypted_payload(self) -> None:
        """Read should return the encrypted vault payload."""

        self.store.create(
            self.secret,
            self.password,
        )

        payload = self.store.read()

        self.assertIsInstance(
            payload,
            bytes,
        )

        self.assertNotEqual(
            payload,
            self.secret,
        )

    def test_read_returns_same_payload(self) -> None:
        """Repeated reads should return identical data."""

        self.store.create(
            self.secret,
            self.password,
        )

        first = self.store.read()
        second = self.store.read()

        self.assertEqual(
            first,
            second,
        )

    def test_read_payload_is_bytes(self) -> None:
        """Vault payload must be bytes."""

        self.store.create(
            self.secret,
            self.password,
        )

        payload = self.store.read()

        self.assertIsInstance(
            payload,
            bytes,
        )

    def test_reading_missing_vault_fails(self) -> None:
        """Reading a missing vault must fail."""

        with self.assertRaises(
            FileNotFoundError
        ):
            self.store.read()

    # ==============================================================
    # SAVE
    # ==============================================================

    def test_save_creates_vault(self) -> None:
        """Save should create a vault."""

        self.store.save(
            self.secret,
            self.password,
        )

        self.assertTrue(
            self.store.exists()
        )

        self.assertEqual(
            self.store.open(self.password),
            self.secret,
        )

    def test_save_replaces_existing_vault(self) -> None:
        """Save should replace an existing vault."""

        first_secret = b"first-secret"
        second_secret = b"second-secret"

        self.store.save(
            first_secret,
            self.password,
        )

        self.store.save(
            second_secret,
            self.password,
        )

        self.assertEqual(
            self.store.open(self.password),
            second_secret,
        )

    def test_save_rejects_invalid_secret(self) -> None:
        """Save must reject invalid secrets."""

        with self.assertRaises(
            (TypeError, ValueError)
        ):
            self.store.save(
                b"",
                self.password,
            )

    # ==============================================================
    # DELETE
    # ==============================================================

    def test_delete_removes_vault(self) -> None:
        """Delete should remove the vault."""

        self.store.create(
            self.secret,
            self.password,
        )

        self.assertTrue(
            self.store.exists()
        )

        self.store.delete()

        self.assertFalse(
            self.store.exists()
        )

    def test_delete_missing_vault_is_safe(self) -> None:
        """Deleting a missing vault should be safe."""

        self.store.delete()

        self.assertFalse(
            self.store.exists()
        )

    # ==============================================================
    # ENCRYPTED DATA
    # ==============================================================

    def test_saved_vault_does_not_contain_plaintext(self) -> None:
        """Saved vault must not expose plaintext."""

        self.store.create(
            self.secret,
            self.password,
        )

        payload = self.store.read()

        self.assertNotIn(
            self.secret,
            payload,
        )

    def test_create_vault_contains_encrypted_data_only(self) -> None:
        """Vault should contain serialized encrypted data."""

        self.store.create(
            self.secret,
            self.password,
        )

        payload = self.store.read()

        self.assertNotEqual(
            payload,
            self.secret,
        )

        self.assertNotEqual(
            payload,
            b"",
        )

    # ==============================================================
    # METADATA
    # ==============================================================

    def test_metadata_contains_no_secret_material(self) -> None:
        """Metadata must not expose secret material."""

        self.store.create(
            self.secret,
            self.password,
        )

        metadata = self.store.metadata()

        serialized = json.dumps(
            metadata
        ).encode("utf-8")

        self.assertNotIn(
            self.secret,
            serialized,
        )

        self.assertNotIn(
            self.password.encode("utf-8"),
            serialized,
        )

    def test_metadata_for_missing_vault_fails(self) -> None:
        """Metadata for a missing vault must fail."""

        with self.assertRaises(
            FileNotFoundError
        ):
            self.store.metadata()

    # ==============================================================
    # VALIDATION
    # ==============================================================

    def test_validate_accepts_valid_vault(self) -> None:
        """A valid vault should pass validation."""

        self.store.create(
            self.secret,
            self.password,
        )

        result = self.store.validate()

        self.assertTrue(
            result
        )

    def test_validate_rejects_corrupted_vault(self) -> None:
        """A corrupted vault should fail validation."""

        self.store.create(
            self.secret,
            self.password,
        )

        self.store.vault_path.write_bytes(
            b"corrupted"
        )

        result = self.store.validate()

        self.assertFalse(
            result
        )

    # ==============================================================
    # ISOLATION
    # ==============================================================

    def test_separate_stores_are_independent(self) -> None:
        """Two stores must not share vault data."""

        other_path = self.create_temp_directory()

        try:
            other_store = KeyStore(
                storage_path=other_path,
            )

            first_secret = b"first-secret"
            second_secret = b"second-secret"

            self.store.create(
                first_secret,
                self.password,
            )

            other_store.create(
                second_secret,
                self.password,
            )

            self.assertEqual(
                self.store.open(
                    self.password
                ),
                first_secret,
            )

            self.assertEqual(
                other_store.open(
                    self.password
                ),
                second_secret,
            )

        finally:
            shutil.rmtree(
                other_path,
                ignore_errors=True,
            )

    # ==============================================================
    # ENCRYPTION DELEGATION
    # ==============================================================

    def test_key_store_delegates_encryption_to_vault_service(
        self,
    ) -> None:
        """KeyStore should use EncryptionService for encryption."""

        with patch.object(
            EncryptionService,
            "encrypt_to_bytes",
            wraps=EncryptionService().encrypt_to_bytes,
        ) as mocked_encrypt:

            self.store.create(
                self.secret,
                self.password,
            )

            self.assertTrue(
                mocked_encrypt.called
            )

    # ==============================================================
    # TEMPORARY FILE SAFETY
    # ==============================================================

    def test_no_temporary_files_remain_after_create(
        self,
    ) -> None:
        """Create should not leave temporary files behind."""

        self.store.create(
            self.secret,
            self.password,
        )

        files = list(
            Path(self.storage_path).iterdir()
        )

        for file_path in files:
            self.assertFalse(
                file_path.name.startswith(".tmp")
                or ".tmp" in file_path.name
            )

    def test_no_temporary_files_remain_after_save(
        self,
    ) -> None:
        """Save should not leave temporary files behind."""

        self.store.save(
            self.secret,
            self.password,
        )

        files = list(
            Path(self.storage_path).iterdir()
        )

        for file_path in files:
            self.assertFalse(
                file_path.name.startswith(".tmp")
                or ".tmp" in file_path.name
            )