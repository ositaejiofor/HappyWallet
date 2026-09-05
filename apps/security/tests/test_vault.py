"""
Tests for the HappyWallet secure wallet vault.

Run:

    python manage.py test apps.security.tests.test_vault
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from apps.security.encryption import (
    EncryptionService,
    InvalidPasswordError,
    InvalidVaultError,
)
from apps.security.vault import (
    VaultFormatError,
    VaultSecretError,
    VaultService,
    WalletSecret,
)


# ============================================================================
# WALLET SECRET TESTS
# ============================================================================


class WalletSecretTestCase(SimpleTestCase):
    """Test WalletSecret validation and serialization."""

    # ------------------------------------------------------------------------
    # VALID SECRETS
    # ------------------------------------------------------------------------

    def test_mnemonic_secret_is_valid(self) -> None:
        """A mnemonic-only secret should be accepted."""

        secret = WalletSecret(
            mnemonic="test mnemonic phrase",
        )

        self.assertEqual(
            secret.mnemonic,
            "test mnemonic phrase",
        )

    def test_private_key_secret_is_valid(self) -> None:
        """A private-key-only secret should be accepted."""

        secret = WalletSecret(
            private_key="0xprivate-key",
        )

        self.assertEqual(
            secret.private_key,
            "0xprivate-key",
        )

    def test_seed_secret_is_valid(self) -> None:
        """A seed-only secret should be accepted."""

        secret = WalletSecret(
            seed="test-seed-material",
        )

        self.assertEqual(
            secret.seed,
            "test-seed-material",
        )

    def test_multiple_secret_fields_are_valid(self) -> None:
        """Multiple supported secret fields may be supplied."""

        secret = WalletSecret(
            mnemonic="test mnemonic",
            private_key="0xprivate-key",
            seed="test-seed",
        )

        secret.validate()

    # ------------------------------------------------------------------------
    # INVALID SECRETS
    # ------------------------------------------------------------------------

    def test_empty_secret_is_rejected_during_construction(self) -> None:
        """
        An empty WalletSecret should fail immediately.

        WalletSecret validates itself in __post_init__, so the exception
        is raised during construction rather than when validate() is called.
        """

        with self.assertRaises(VaultSecretError):
            WalletSecret()

    def test_empty_mnemonic_is_rejected(self) -> None:
        """A blank mnemonic should be rejected."""

        with self.assertRaises(VaultSecretError):
            WalletSecret(
                mnemonic="   ",
            )

    def test_empty_private_key_is_rejected(self) -> None:
        """A blank private key should be rejected."""

        with self.assertRaises(VaultSecretError):
            WalletSecret(
                private_key="",
            )

    def test_empty_seed_is_rejected(self) -> None:
        """A blank seed should be rejected."""

        with self.assertRaises(VaultSecretError):
            WalletSecret(
                seed="   ",
            )

    def test_invalid_mnemonic_type_is_rejected(self) -> None:
        """Mnemonic must be a string or None."""

        with self.assertRaises(VaultSecretError):
            WalletSecret(
                mnemonic=123,  # type: ignore[arg-type]
            )

    def test_invalid_private_key_type_is_rejected(self) -> None:
        """Private key must be a string or None."""

        with self.assertRaises(VaultSecretError):
            WalletSecret(
                private_key=123,  # type: ignore[arg-type]
            )

    def test_invalid_seed_type_is_rejected(self) -> None:
        """Seed must be a string or None."""

        with self.assertRaises(VaultSecretError):
            WalletSecret(
                seed=123,  # type: ignore[arg-type]
            )

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    def test_validate_accepts_valid_secret(self) -> None:
        """Explicit validation should succeed for a valid secret."""

        secret = WalletSecret(
            mnemonic="test mnemonic",
        )

        result = secret.validate()

        self.assertIsNone(result)

    # ------------------------------------------------------------------------
    # SERIALIZATION
    # ------------------------------------------------------------------------

    def test_secret_serialization_round_trip(self) -> None:
        """A WalletSecret should survive serialization and restoration."""

        secret = WalletSecret(
            mnemonic="test mnemonic",
            private_key="0xprivate-key",
            seed="test-seed",
        )

        payload = secret.to_bytes()

        restored = WalletSecret.from_bytes(
            payload,
        )

        self.assertEqual(
            restored,
            secret,
        )

    def test_serialized_secret_is_bytes(self) -> None:
        """Secret serialization should return bytes."""

        secret = WalletSecret(
            mnemonic="test mnemonic",
        )

        payload = secret.to_bytes()

        self.assertIsInstance(
            payload,
            bytes,
        )

    def test_serialized_secret_contains_expected_fields(self) -> None:
        """Serialized secret should contain only supported fields."""

        secret = WalletSecret(
            mnemonic="test mnemonic",
        )

        document = json.loads(
            secret.to_bytes().decode("utf-8"),
        )

        self.assertEqual(
            set(document),
            {
                "mnemonic",
                "private_key",
                "seed",
            },
        )

        self.assertEqual(
            document["mnemonic"],
            "test mnemonic",
        )

    # ------------------------------------------------------------------------
    # DESERIALIZATION
    # ------------------------------------------------------------------------

    def test_invalid_secret_json_is_rejected(self) -> None:
        """Malformed JSON must be rejected."""

        with self.assertRaises(VaultFormatError):
            WalletSecret.from_bytes(
                b"not valid json",
            )

    def test_empty_secret_payload_is_rejected(self) -> None:
        """Empty decrypted secret data must be rejected."""

        with self.assertRaises(VaultFormatError):
            WalletSecret.from_bytes(
                b"",
            )

    def test_secret_json_must_be_object(self) -> None:
        """Decrypted secret JSON must contain an object."""

        payload = json.dumps(
            ["not", "an", "object"],
        ).encode("utf-8")

        with self.assertRaises(VaultFormatError):
            WalletSecret.from_bytes(
                payload,
            )

    def test_secret_json_rejects_unsupported_fields(self) -> None:
        """Unknown secret fields must not be accepted."""

        payload = json.dumps(
            {
                "mnemonic": "test mnemonic",
                "unexpected": "secret",
            },
        ).encode("utf-8")

        with self.assertRaises(VaultFormatError):
            WalletSecret.from_bytes(
                payload,
            )

    def test_secret_payload_must_be_bytes(self) -> None:
        """from_bytes must reject non-byte input."""

        with self.assertRaises(TypeError):
            WalletSecret.from_bytes(
                "not bytes",  # type: ignore[arg-type]
            )


# ============================================================================
# VAULT SERVICE TESTS
# ============================================================================


class VaultServiceTestCase(SimpleTestCase):
    """Test VaultService encryption, decryption, and validation."""

    def setUp(self) -> None:
        self.encryption = EncryptionService()

        self.vault = VaultService(
            encryption_service=self.encryption,
        )

        self.password = (
            "correct horse battery staple"
        )

        self.secret = WalletSecret(
            mnemonic=(
                "abandon abandon abandon abandon "
                "abandon abandon abandon abandon "
                "abandon abandon abandon about"
            ),
            private_key="0x0123456789abcdef",
            seed="test-seed-material",
        )

    # ========================================================================
    # CREATE
    # ========================================================================

    def test_create_vault_returns_bytes(self) -> None:
        """Creating a vault should return serialized bytes."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.assertIsInstance(
            payload,
            bytes,
        )

        self.assertTrue(
            payload,
        )

    def test_create_vault_requires_wallet_secret(self) -> None:
        """create_vault must receive WalletSecret."""

        with self.assertRaises(TypeError):
            self.vault.create_vault(
                "not a secret",  # type: ignore[arg-type]
                self.password,
            )

    def test_create_vault_rejects_invalid_secret(self) -> None:
        """Invalid WalletSecret objects cannot be encrypted."""

        with self.assertRaises(VaultSecretError):
            WalletSecret()

    def test_create_vault_does_not_store_plaintext(self) -> None:
        """Plaintext secret material must not appear in ciphertext."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.assertNotIn(
            self.secret.mnemonic.encode("utf-8"),
            payload,
        )

        self.assertNotIn(
            self.secret.private_key.encode("utf-8"),
            payload,
        )

        self.assertNotIn(
            self.secret.seed.encode("utf-8"),
            payload,
        )

        self.assertNotIn(
            self.password.encode("utf-8"),
            payload,
        )

    # ========================================================================
    # OPEN
    # ========================================================================

    def test_open_vault_round_trip(self) -> None:
        """A created vault should decrypt to the original secret."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        restored = self.vault.open_vault(
            payload,
            self.password,
        )

        self.assertEqual(
            restored,
            self.secret,
        )

    def test_wrong_password_is_rejected(self) -> None:
        """An incorrect password must fail authentication."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        with self.assertRaises(
            InvalidPasswordError,
        ):
            self.vault.open_vault(
                payload,
                "completely-wrong-password",
            )

    def test_modified_vault_is_rejected(self) -> None:
        """Authenticated ciphertext modification must be rejected."""

        payload = bytearray(
            self.vault.create_vault(
                self.secret,
                self.password,
            ),
        )

        payload[-1] ^= 1

        with self.assertRaises(
            (
                InvalidPasswordError,
                InvalidVaultError,
                VaultFormatError,
            ),
        ):
            self.vault.open_vault(
                bytes(payload),
                self.password,
            )

    def test_empty_payload_is_rejected(self) -> None:
        """An empty encrypted vault must be rejected."""

        with self.assertRaises(
            (
                InvalidVaultError,
                VaultFormatError,
            ),
        ):
            self.vault.open_vault(
                b"",
                self.password,
            )

    def test_non_bytes_payload_is_rejected(self) -> None:
        """Encrypted vault payload must be bytes."""

        with self.assertRaises(TypeError):
            self.vault.open_vault(
                "invalid payload",  # type: ignore[arg-type]
                self.password,
            )

    # ========================================================================
    # VAULT VALIDATION
    # ========================================================================

    def test_validate_vault_accepts_valid_payload(self) -> None:
        """A structurally valid vault should pass validation."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        result = self.vault.validate_vault(
            payload,
        )

        self.assertIsNone(
            result,
        )

    def test_validate_vault_does_not_require_password(self) -> None:
        """
        Structural validation should not require the wallet password.
        """

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.vault.validate_vault(
            payload,
        )

    def test_validate_vault_rejects_invalid_payload(self) -> None:
        """Malformed encrypted data must fail structural validation."""

        with self.assertRaises(
            InvalidVaultError,
        ):
            self.vault.validate_vault(
                b"invalid vault",
            )

    def test_validate_vault_rejects_empty_payload(self) -> None:
        """Empty payloads must fail validation."""

        with self.assertRaises(
            VaultFormatError,
        ):
            self.vault.validate_vault(
                b"",
            )

    # ========================================================================
    # ASSOCIATED DATA
    # ========================================================================

    def test_associated_data_is_used_for_encryption(self) -> None:
        """
        The vault should use authenticated associated data.

        A normal round trip confirms the configured AAD is accepted.
        """

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        restored = self.vault.open_vault(
            payload,
            self.password,
        )

        self.assertEqual(
            restored.private_key,
            self.secret.private_key,
        )

    # ========================================================================
    # VAULT FORMAT
    # ========================================================================

    def test_vault_format_identifier(self) -> None:
        """Vault format identifier should remain stable."""

        self.assertEqual(
            self.vault.FORMAT,
            "happywallet-wallet-vault",
        )

    def test_vault_version(self) -> None:
        """Vault version should remain stable."""

        self.assertEqual(
            self.vault.VERSION,
            1,
        )

    def test_vault_payload_has_expected_format(self) -> None:
        """Encrypted vault should contain the expected envelope format."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        document = json.loads(
            payload.decode("utf-8"),
        )

        self.assertEqual(
            document["format"],
            self.encryption.FORMAT,
        )

        self.assertEqual(
            document["version"],
            self.encryption.VERSION,
        )

        self.assertIn(
            "data",
            document,
        )

    def test_vault_payload_is_deserializable(self) -> None:
        """EncryptionService should recognize the vault envelope."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        envelope = self.encryption.deserialize(
            payload,
        )

        self.assertIsNotNone(
            envelope,
        )

    # ========================================================================
    # SECURITY
    # ========================================================================

    def test_two_vaults_have_different_ciphertext(self) -> None:
        """
        Encrypting identical secrets twice should produce different output.

        This verifies that fresh random cryptographic material is used.
        """

        first = self.vault.create_vault(
            self.secret,
            self.password,
        )

        second = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.assertNotEqual(
            first,
            second,
        )

    def test_private_key_is_recovered_only_after_decryption(self) -> None:
        """Private key should only be available after successful decryption."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.assertNotIn(
            self.secret.private_key.encode("utf-8"),
            payload,
        )

        restored = self.vault.open_vault(
            payload,
            self.password,
        )

        self.assertEqual(
            restored.private_key,
            self.secret.private_key,
        )

    def test_mnemonic_is_recovered_only_after_decryption(self) -> None:
        """Mnemonic should only be available after successful decryption."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.assertNotIn(
            self.secret.mnemonic.encode("utf-8"),
            payload,
        )

        restored = self.vault.open_vault(
            payload,
            self.password,
        )

        self.assertEqual(
            restored.mnemonic,
            self.secret.mnemonic,
        )

    def test_seed_is_recovered_only_after_decryption(self) -> None:
        """Seed should only be available after successful decryption."""

        payload = self.vault.create_vault(
            self.secret,
            self.password,
        )

        self.assertNotIn(
            self.secret.seed.encode("utf-8"),
            payload,
        )

        restored = self.vault.open_vault(
            payload,
            self.password,
        )

        self.assertEqual(
            restored.seed,
            self.secret.seed,
        )