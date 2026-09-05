"""
Tests for HappyWallet vault encryption.

Run:

    python manage.py test apps.security.tests.test_encryption
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from apps.security.encryption import (
    EncryptedBlob,
    EncryptionService,
    InvalidPasswordError,
    InvalidVaultError,
)


class EncryptionServiceTestCase(SimpleTestCase):
    """Test HappyWallet's encryption service."""

    def setUp(self) -> None:
        self.service = EncryptionService()

        self.password = "correct horse battery staple"

        self.plaintext = (
            b"happywallet-sensitive-wallet-material"
        )

    # ==================================================================
    # PASSWORD
    # ==================================================================

    def test_valid_password(self) -> None:
        self.service.validate_password(
            self.password
        )

    def test_empty_password_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.validate_password("")

    def test_short_password_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.validate_password("short")

    def test_non_string_password_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.service.validate_password(
                12345678  # type: ignore[arg-type]
            )

    # ==================================================================
    # SCRYPT
    # ==================================================================

    def test_scrypt_n_must_be_power_of_two(self) -> None:
        with self.assertRaises(ValueError):
            EncryptionService(
                n=1000,
                r=8,
                p=1,
            )

    def test_scrypt_n_must_be_greater_than_one(self) -> None:
        with self.assertRaises(ValueError):
            EncryptionService(
                n=1,
                r=8,
                p=1,
            )

    def test_scrypt_r_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            EncryptionService(
                n=2**10,
                r=0,
                p=1,
            )

    def test_scrypt_p_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            EncryptionService(
                n=2**10,
                r=8,
                p=0,
            )

    def test_key_derivation_is_deterministic(self) -> None:
        salt = b"0123456789abcdef"

        key_one = self.service.derive_key(
            self.password,
            salt,
        )

        key_two = self.service.derive_key(
            self.password,
            salt,
        )

        self.assertEqual(key_one, key_two)

        self.assertEqual(
            len(key_one),
            EncryptionService.KEY_SIZE,
        )

    def test_different_salts_produce_different_keys(self) -> None:
        key_one = self.service.derive_key(
            self.password,
            b"0123456789abcdef",
        )

        key_two = self.service.derive_key(
            self.password,
            b"fedcba9876543210",
        )

        self.assertNotEqual(key_one, key_two)

    # ==================================================================
    # ENCRYPTION
    # ==================================================================

    def test_encrypt_returns_encrypted_blob(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        self.assertIsInstance(
            blob,
            EncryptedBlob,
        )

    def test_salt_has_correct_size(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        self.assertEqual(
            len(blob.salt),
            EncryptionService.SALT_SIZE,
        )

    def test_nonce_has_correct_size(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        self.assertEqual(
            len(blob.nonce),
            EncryptionService.NONCE_SIZE,
        )

    def test_ciphertext_is_not_plaintext(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        self.assertNotEqual(
            blob.ciphertext,
            self.plaintext,
        )

        self.assertNotIn(
            self.plaintext,
            blob.ciphertext,
        )

    def test_empty_plaintext_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.encrypt(
                b"",
                self.password,
            )

    def test_non_bytes_plaintext_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.service.encrypt(
                "sensitive data",  # type: ignore[arg-type]
                self.password,
            )

    def test_each_encryption_uses_new_salt_and_nonce(self) -> None:
        first = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        second = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        self.assertNotEqual(
            first.salt,
            second.salt,
        )

        self.assertNotEqual(
            first.nonce,
            second.nonce,
        )

        self.assertNotEqual(
            first.ciphertext,
            second.ciphertext,
        )

    # ==================================================================
    # DECRYPTION
    # ==================================================================

    def test_encrypt_decrypt_round_trip(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        decrypted = self.service.decrypt(
            blob,
            self.password,
        )

        self.assertEqual(
            decrypted,
            self.plaintext,
        )

    def test_wrong_password_fails(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.service.decrypt(
                blob,
                "wrong password completely",
            )

    def test_modified_ciphertext_fails(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        ciphertext = bytearray(
            blob.ciphertext
        )

        ciphertext[0] ^= 1

        modified_blob = EncryptedBlob(
            salt=blob.salt,
            nonce=blob.nonce,
            ciphertext=bytes(ciphertext),
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.service.decrypt(
                modified_blob,
                self.password,
            )

    def test_modified_nonce_fails(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        nonce = bytearray(blob.nonce)

        nonce[0] ^= 1

        modified_blob = EncryptedBlob(
            salt=blob.salt,
            nonce=bytes(nonce),
            ciphertext=blob.ciphertext,
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.service.decrypt(
                modified_blob,
                self.password,
            )

    def test_modified_salt_fails(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        salt = bytearray(blob.salt)

        salt[0] ^= 1

        modified_blob = EncryptedBlob(
            salt=bytes(salt),
            nonce=blob.nonce,
            ciphertext=blob.ciphertext,
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.service.decrypt(
                modified_blob,
                self.password,
            )

    # ==================================================================
    # ASSOCIATED DATA
    # ==================================================================

    def test_associated_data_round_trip(self) -> None:
        associated_data = (
            b"happywallet-vault-v1"
        )

        blob = self.service.encrypt(
            self.plaintext,
            self.password,
            associated_data=associated_data,
        )

        decrypted = self.service.decrypt(
            blob,
            self.password,
            associated_data=associated_data,
        )

        self.assertEqual(
            decrypted,
            self.plaintext,
        )

    def test_wrong_associated_data_fails(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
            associated_data=b"wallet-v1",
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.service.decrypt(
                blob,
                self.password,
                associated_data=b"wallet-v2",
            )

    # ==================================================================
    # ENCRYPTED BLOB
    # ==================================================================

    def test_blob_serialization_round_trip(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        data = blob.to_dict()

        restored = EncryptedBlob.from_dict(
            data
        )

        self.assertEqual(
            restored,
            blob,
        )

    def test_invalid_blob_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidVaultError
        ):
            EncryptedBlob.from_dict(
                {
                    "salt": "invalid",
                    "nonce": "invalid",
                    "ciphertext": "invalid",
                }
            )

    # ==================================================================
    # VAULT SERIALIZATION
    # ==================================================================

    def test_vault_serialization_round_trip(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        payload = self.service.serialize(
            blob
        )

        restored = self.service.deserialize(
            payload
        )

        self.assertEqual(
            restored,
            blob,
        )

    def test_vault_is_valid_json(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        payload = self.service.serialize(
            blob
        )

        document = json.loads(
            payload.decode("utf-8")
        )

        self.assertEqual(
            document["format"],
            "happywallet-vault",
        )

        self.assertEqual(
            document["version"],
            EncryptionService.VERSION,
        )

    def test_vault_uses_scrypt(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        payload = self.service.serialize(
            blob
        )

        document = json.loads(
            payload.decode("utf-8")
        )

        self.assertEqual(
            document["kdf"]["name"],
            "scrypt",
        )

    def test_vault_uses_aes_256_gcm(self) -> None:
        blob = self.service.encrypt(
            self.plaintext,
            self.password,
        )

        payload = self.service.serialize(
            blob
        )

        document = json.loads(
            payload.decode("utf-8")
        )

        self.assertEqual(
            document["encryption"]["algorithm"],
            "AES-256-GCM",
        )

    # ==================================================================
    # COMPLETE API
    # ==================================================================

    def test_encrypt_to_bytes_and_decrypt_from_bytes(
        self,
    ) -> None:
        payload = self.service.encrypt_to_bytes(
            self.plaintext,
            self.password,
        )

        decrypted = self.service.decrypt_from_bytes(
            payload,
            self.password,
        )

        self.assertEqual(
            decrypted,
            self.plaintext,
        )

    def test_complete_api_supports_associated_data(
        self,
    ) -> None:
        associated_data = (
            b"happywallet-wallet-001"
        )

        payload = self.service.encrypt_to_bytes(
            self.plaintext,
            self.password,
            associated_data=associated_data,
        )

        decrypted = self.service.decrypt_from_bytes(
            payload,
            self.password,
            associated_data=associated_data,
        )

        self.assertEqual(
            decrypted,
            self.plaintext,
        )

    # ==================================================================
    # VAULT VALIDATION
    # ==================================================================

    def test_invalid_vault_format_is_rejected(self) -> None:
        payload = json.dumps(
            {
                "format": "invalid-format",
                "version": 1,
            }
        ).encode("utf-8")

        with self.assertRaises(
            InvalidVaultError
        ):
            self.service.deserialize(payload)

    def test_invalid_vault_version_is_rejected(self) -> None:
        payload = json.dumps(
            {
                "format": "happywallet-vault",
                "version": 999,
            }
        ).encode("utf-8")

        with self.assertRaises(
            InvalidVaultError
        ):
            self.service.deserialize(payload)

    def test_invalid_kdf_is_rejected(self) -> None:
        payload = json.dumps(
            {
                "format": "happywallet-vault",
                "version": 1,
                "kdf": {
                    "name": "pbkdf2",
                },
            }
        ).encode("utf-8")

        with self.assertRaises(
            InvalidVaultError
        ):
            self.service.deserialize(payload)

    def test_invalid_encryption_algorithm_is_rejected(
        self,
    ) -> None:
        payload = json.dumps(
            {
                "format": "happywallet-vault",
                "version": 1,
                "kdf": {
                    "name": "scrypt",
                },
                "encryption": {
                    "algorithm": "AES-128-CBC",
                },
            }
        ).encode("utf-8")

        with self.assertRaises(
            InvalidVaultError
        ):
            self.service.deserialize(payload)

    def test_invalid_json_is_rejected(self) -> None:
        with self.assertRaises(
            InvalidVaultError
        ):
            self.service.deserialize(
                b"this is not valid json"
            )

    # ==================================================================
    # SECURITY PROPERTIES
    # ==================================================================

    def test_serialized_vault_does_not_contain_plaintext(
        self,
    ) -> None:
        payload = self.service.encrypt_to_bytes(
            self.plaintext,
            self.password,
        )

        self.assertNotIn(
            self.plaintext,
            payload,
        )

    def test_serialized_vault_does_not_contain_password(
        self,
    ) -> None:
        payload = self.service.encrypt_to_bytes(
            self.plaintext,
            self.password,
        )

        self.assertNotIn(
            self.password.encode("utf-8"),
            payload,
        )