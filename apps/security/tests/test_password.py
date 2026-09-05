"""
Tests for HappyWallet password and PIN security.

These tests verify:

    - password policy enforcement
    - PIN policy enforcement
    - secure password hashing
    - secure PIN hashing
    - password verification
    - PIN verification
    - random salts
    - malformed verifier rejection
    - tamper detection
    - version and algorithm validation
    - rehash detection
    - serialization round-trips
"""

from __future__ import annotations

import base64
from unittest import TestCase
from unittest.mock import patch

from apps.security.password import (
    InvalidPasswordError,
    InvalidPasswordHashError,
    PasswordHash,
    PasswordSecurityError,
    PasswordService,
)


class PasswordHashTests(TestCase):
    """Tests for the immutable PasswordHash value object."""

    def setUp(self) -> None:
        self.salt = b"s" * PasswordHash.SALT_SIZE
        self.digest = b"d" * PasswordHash.DIGEST_SIZE

    def test_valid_password_hash_can_be_created(self) -> None:
        password_hash = PasswordHash(
            version=1,
            algorithm=PasswordHash.ALGORITHM,
            iterations=600_000,
            salt=self.salt,
            digest=self.digest,
        )

        self.assertEqual(password_hash.version, 1)
        self.assertEqual(
            password_hash.algorithm,
            PasswordHash.ALGORITHM,
        )
        self.assertEqual(password_hash.iterations, 600_000)
        self.assertEqual(password_hash.salt, self.salt)
        self.assertEqual(password_hash.digest, self.digest)

    def test_password_hash_is_immutable(self) -> None:
        password_hash = PasswordHash(
            version=1,
            algorithm=PasswordHash.ALGORITHM,
            iterations=600_000,
            salt=self.salt,
            digest=self.digest,
        )

        with self.assertRaises(AttributeError):
            password_hash.salt = b"x" * PasswordHash.SALT_SIZE  # type: ignore[misc]

    def test_invalid_version_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PasswordHash(
                version=999,
                algorithm=PasswordHash.ALGORITHM,
                iterations=600_000,
                salt=self.salt,
                digest=self.digest,
            )

    def test_invalid_algorithm_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PasswordHash(
                version=1,
                algorithm="UNSUPPORTED",
                iterations=600_000,
                salt=self.salt,
                digest=self.digest,
            )

    def test_invalid_iterations_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordHash(
                version=1,
                algorithm=PasswordHash.ALGORITHM,
                iterations="600000",  # type: ignore[arg-type]
                salt=self.salt,
                digest=self.digest,
            )

    def test_non_positive_iterations_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PasswordHash(
                version=1,
                algorithm=PasswordHash.ALGORITHM,
                iterations=0,
                salt=self.salt,
                digest=self.digest,
            )

    def test_invalid_salt_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordHash(
                version=1,
                algorithm=PasswordHash.ALGORITHM,
                iterations=600_000,
                salt="invalid",  # type: ignore[arg-type]
                digest=self.digest,
            )

    def test_invalid_salt_length_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PasswordHash(
                version=1,
                algorithm=PasswordHash.ALGORITHM,
                iterations=600_000,
                salt=b"short",
                digest=self.digest,
            )

    def test_invalid_digest_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordHash(
                version=1,
                algorithm=PasswordHash.ALGORITHM,
                iterations=600_000,
                salt=self.salt,
                digest="invalid",  # type: ignore[arg-type]
            )

    def test_invalid_digest_length_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PasswordHash(
                version=1,
                algorithm=PasswordHash.ALGORITHM,
                iterations=600_000,
                salt=self.salt,
                digest=b"short",
            )


class PasswordHashSerializationTests(TestCase):
    """Tests for password verifier serialization."""

    def setUp(self) -> None:
        self.password_hash = PasswordHash(
            version=1,
            algorithm=PasswordHash.ALGORITHM,
            iterations=600_000,
            salt=b"s" * PasswordHash.SALT_SIZE,
            digest=b"d" * PasswordHash.DIGEST_SIZE,
        )

    def test_serialize_returns_string(self) -> None:
        serialized = self.password_hash.serialize()

        self.assertIsInstance(serialized, str)

    def test_serialized_value_has_expected_prefix(self) -> None:
        serialized = self.password_hash.serialize()

        self.assertTrue(
            serialized.startswith("hw-pwd$")
        )

    def test_round_trip_preserves_values(self) -> None:
        serialized = self.password_hash.serialize()

        restored = PasswordHash.deserialize(
            serialized
        )

        self.assertEqual(
            restored,
            self.password_hash,
        )

    def test_deserialize_rejects_non_string(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(  # type: ignore[arg-type]
                b"invalid"
            )

    def test_deserialize_rejects_empty_string(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize("")

    def test_deserialize_rejects_wrong_prefix(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                "wrong$1$PBKDF2-HMAC-SHA256$600000$abc$def"
            )

    def test_deserialize_rejects_wrong_number_of_fields(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                "hw-pwd$1$PBKDF2-HMAC-SHA256$600000$abc"
            )

    def test_deserialize_rejects_invalid_version(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                "hw-pwd$999$PBKDF2-HMAC-SHA256$600000$"
                + base64.b64encode(
                    b"s" * PasswordHash.SALT_SIZE
                ).decode()
                + "$"
                + base64.b64encode(
                    b"d" * PasswordHash.DIGEST_SIZE
                ).decode()
            )

    def test_deserialize_rejects_invalid_iterations(self) -> None:
        salt = base64.b64encode(
            b"s" * PasswordHash.SALT_SIZE
        ).decode()

        digest = base64.b64encode(
            b"d" * PasswordHash.DIGEST_SIZE
        ).decode()

        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                f"hw-pwd$1$PBKDF2-HMAC-SHA256$invalid$"
                f"{salt}${digest}"
            )

    def test_deserialize_rejects_invalid_base64(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                "hw-pwd$1$PBKDF2-HMAC-SHA256$600000$%%%$%%%"
            )

    def test_deserialize_rejects_invalid_salt_length(self) -> None:
        digest = base64.b64encode(
            b"d" * PasswordHash.DIGEST_SIZE
        ).decode()

        salt = base64.b64encode(
            b"short"
        ).decode()

        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                f"hw-pwd$1$PBKDF2-HMAC-SHA256$600000$"
                f"{salt}${digest}"
            )

    def test_deserialize_rejects_invalid_digest_length(self) -> None:
        salt = base64.b64encode(
            b"s" * PasswordHash.SALT_SIZE
        ).decode()

        digest = base64.b64encode(
            b"short"
        ).decode()

        with self.assertRaises(InvalidPasswordHashError):
            PasswordHash.deserialize(
                f"hw-pwd$1$PBKDF2-HMAC-SHA256$600000$"
                f"{salt}${digest}"
            )


class PasswordValidationTests(TestCase):
    """Tests for password policy enforcement."""

    def test_valid_password_is_accepted(self) -> None:
        PasswordService.validate_password(
            "Correct-Horse-Battery"
        )

    def test_password_at_minimum_length_is_accepted(self) -> None:
        PasswordService.validate_password(
            "a" * PasswordService.MIN_PASSWORD_LENGTH
        )

    def test_short_password_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_password(
                "short"
            )

    def test_empty_password_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_password("")

    def test_non_string_password_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordService.validate_password(  # type: ignore[arg-type]
                None
            )

    def test_password_above_maximum_length_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_password(
                "a" * (PasswordService.MAX_PASSWORD_LENGTH + 1)
            )

    def test_unicode_password_is_supported(self) -> None:
        PasswordService.validate_password(
            "Sécurisé-Passphrase-2026"
        )


class PinValidationTests(TestCase):
    """Tests for wallet PIN policy."""

    def test_valid_pin_is_accepted(self) -> None:
        PasswordService.validate_pin("123456")

    def test_long_valid_pin_is_accepted(self) -> None:
        PasswordService.validate_pin(
            "1" * PasswordService.MAX_PIN_LENGTH
        )

    def test_short_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_pin("12345")

    def test_empty_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_pin("")

    def test_non_string_pin_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordService.validate_pin(123456)  # type: ignore[arg-type]

    def test_non_digit_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_pin("12345a")

    def test_unicode_digit_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_pin("１２３４５６")

    def test_pin_above_maximum_length_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordError):
            PasswordService.validate_pin(
                "1" * (PasswordService.MAX_PIN_LENGTH + 1)
            )


class PasswordHashingTests(TestCase):
    """Tests for password hashing."""

    PASSWORD = "Correct-Horse-Battery"

    def test_hash_password_returns_string(self) -> None:
        result = PasswordService.hash_password(
            self.PASSWORD
        )

        self.assertIsInstance(result, str)

    def test_hash_has_expected_prefix(self) -> None:
        result = PasswordService.hash_password(
            self.PASSWORD
        )

        self.assertTrue(
            result.startswith("hw-pwd$")
        )

    def test_same_password_produces_different_hashes(self) -> None:
        first = PasswordService.hash_password(
            self.PASSWORD
        )

        second = PasswordService.hash_password(
            self.PASSWORD
        )

        self.assertNotEqual(
            first,
            second,
        )

    def test_different_passwords_produce_different_hashes(self) -> None:
        first = PasswordService.hash_password(
            self.PASSWORD
        )

        second = PasswordService.hash_password(
            "Completely-Different-Password"
        )

        self.assertNotEqual(
            first,
            second,
        )

    def test_plaintext_password_is_not_present_in_hash(self) -> None:
        result = PasswordService.hash_password(
            self.PASSWORD
        )

        self.assertNotIn(
            self.PASSWORD,
            result,
        )

    def test_hash_can_be_deserialized(self) -> None:
        result = PasswordService.hash_password(
            self.PASSWORD
        )

        parsed = PasswordHash.deserialize(result)

        self.assertEqual(
            parsed.iterations,
            PasswordService.ITERATIONS,
        )

        self.assertEqual(
            len(parsed.salt),
            PasswordService.SALT_SIZE,
        )

        self.assertEqual(
            len(parsed.digest),
            PasswordService.DIGEST_SIZE,
        )


class PasswordVerificationTests(TestCase):
    """Tests for password verification."""

    PASSWORD = "Correct-Horse-Battery"

    def setUp(self) -> None:
        self.stored_hash = PasswordService.hash_password(
            self.PASSWORD
        )

    def test_correct_password_verifies(self) -> None:
        self.assertTrue(
            PasswordService.verify_password(
                self.PASSWORD,
                self.stored_hash,
            )
        )

    def test_wrong_password_does_not_verify(self) -> None:
        self.assertFalse(
            PasswordService.verify_password(
                "Wrong-Password-Here",
                self.stored_hash,
            )
        )

    def test_tampered_digest_does_not_verify(self) -> None:
        parsed = PasswordHash.deserialize(
            self.stored_hash
        )

        tampered_digest = bytes(
            value ^ 1
            for value in parsed.digest
        )

        tampered = PasswordHash(
            version=parsed.version,
            algorithm=parsed.algorithm,
            iterations=parsed.iterations,
            salt=parsed.salt,
            digest=tampered_digest,
        ).serialize()

        self.assertFalse(
            PasswordService.verify_password(
                self.PASSWORD,
                tampered,
            )
        )

    def test_tampered_salt_does_not_verify(self) -> None:
        parsed = PasswordHash.deserialize(
            self.stored_hash
        )

        tampered_salt = bytes(
            value ^ 1
            for value in parsed.salt
        )

        tampered = PasswordHash(
            version=parsed.version,
            algorithm=parsed.algorithm,
            iterations=parsed.iterations,
            salt=tampered_salt,
            digest=parsed.digest,
        ).serialize()

        self.assertFalse(
            PasswordService.verify_password(
                self.PASSWORD,
                tampered,
            )
        )

    def test_malformed_hash_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordService.verify_password(
                self.PASSWORD,
                "invalid",
            )

    def test_empty_hash_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordService.verify_password(
                self.PASSWORD,
                "",
            )


class PinHashingTests(TestCase):
    """Tests for PIN hashing and verification."""

    PIN = "482913"

    def test_hash_pin_returns_string(self) -> None:
        result = PasswordService.hash_pin(
            self.PIN
        )

        self.assertIsInstance(result, str)

    def test_correct_pin_verifies(self) -> None:
        stored_hash = PasswordService.hash_pin(
            self.PIN
        )

        self.assertTrue(
            PasswordService.verify_pin(
                self.PIN,
                stored_hash,
            )
        )

    def test_wrong_pin_does_not_verify(self) -> None:
        stored_hash = PasswordService.hash_pin(
            self.PIN
        )

        self.assertFalse(
            PasswordService.verify_pin(
                "123456",
                stored_hash,
            )
        )

    def test_same_pin_gets_different_hashes(self) -> None:
        first = PasswordService.hash_pin(
            self.PIN
        )

        second = PasswordService.hash_pin(
            self.PIN
        )

        self.assertNotEqual(
            first,
            second,
        )

    def test_pin_is_not_stored_as_plaintext(self) -> None:
        result = PasswordService.hash_pin(
            self.PIN
        )

        self.assertNotIn(
            self.PIN,
            result,
        )

    def test_malformed_pin_hash_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordHashError):
            PasswordService.verify_pin(
                self.PIN,
                "invalid",
            )


class ConstantTimeVerificationTests(TestCase):
    """Tests that verification uses constant-time comparison."""

    def test_password_verification_uses_compare_digest(self) -> None:
        stored_hash = PasswordService.hash_password(
            "Correct-Horse-Battery"
        )

        with patch(
            "apps.security.password.hmac.compare_digest",
            wraps=__import__(
                "hmac"
            ).compare_digest,
        ) as compare_digest:
            result = PasswordService.verify_password(
                "Correct-Horse-Battery",
                stored_hash,
            )

        self.assertTrue(result)
        compare_digest.assert_called_once()

    def test_pin_verification_uses_compare_digest(self) -> None:
        stored_hash = PasswordService.hash_pin(
            "482913"
        )

        with patch(
            "apps.security.password.hmac.compare_digest",
            wraps=__import__(
                "hmac"
            ).compare_digest,
        ) as compare_digest:
            result = PasswordService.verify_pin(
                "482913",
                stored_hash,
            )

        self.assertTrue(result)
        compare_digest.assert_called_once()


class RehashTests(TestCase):
    """Tests for password verifier upgrade detection."""

    PASSWORD = "Correct-Horse-Battery"

    def test_current_hash_does_not_need_rehash(self) -> None:
        stored_hash = PasswordService.hash_password(
            self.PASSWORD
        )

        self.assertFalse(
            PasswordService.needs_rehash(
                stored_hash
            )
        )

    def test_different_iteration_count_needs_rehash(self) -> None:
        salt = b"s" * PasswordService.SALT_SIZE

        digest = PasswordService._derive(
            password=self.PASSWORD,
            salt=salt,
            iterations=100_000,
        )

        stored_hash = PasswordHash(
            version=PasswordService.VERSION,
            algorithm=PasswordService.ALGORITHM,
            iterations=100_000,
            salt=salt,
            digest=digest,
        ).serialize()

        self.assertTrue(
            PasswordService.needs_rehash(
                stored_hash
            )
        )

    def test_different_version_needs_rehash(self) -> None:
        salt = b"s" * PasswordService.SALT_SIZE
        digest = b"d" * PasswordService.DIGEST_SIZE

        value = (
            "hw-pwd$999$PBKDF2-HMAC-SHA256$600000$"
            f"{base64.b64encode(salt).decode()}$"
            f"{base64.b64encode(digest).decode()}"
        )

        with self.assertRaises(InvalidPasswordHashError):
            PasswordService.needs_rehash(value)


class PasswordSecurityErrorTests(TestCase):
    """Tests for exception hierarchy."""

    def test_invalid_password_error_is_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                InvalidPasswordError,
                PasswordSecurityError,
            )
        )

    def test_invalid_hash_error_is_security_error(self) -> None:
        self.assertTrue(
            issubclass(
                InvalidPasswordHashError,
                PasswordSecurityError,
            )
        )


class InternalDerivationTests(TestCase):
    """Tests for the internal PBKDF2 derivation boundary."""

    def test_derive_returns_expected_digest_length(self) -> None:
        digest = PasswordService._derive(
            password="Correct-Horse-Battery",
            salt=b"s" * PasswordService.SALT_SIZE,
            iterations=1_000,
        )

        self.assertEqual(
            len(digest),
            PasswordService.DIGEST_SIZE,
        )

    def test_derive_rejects_invalid_salt_type(self) -> None:
        with self.assertRaises(TypeError):
            PasswordService._derive(
                password="Correct-Horse-Battery",
                salt="invalid",  # type: ignore[arg-type]
                iterations=1_000,
            )

    def test_derive_rejects_invalid_salt_length(self) -> None:
        with self.assertRaises(ValueError):
            PasswordService._derive(
                password="Correct-Horse-Battery",
                salt=b"short",
                iterations=1_000,
            )

    def test_derive_rejects_invalid_iterations_type(self) -> None:
        with self.assertRaises(TypeError):
            PasswordService._derive(
                password="Correct-Horse-Battery",
                salt=b"s" * PasswordService.SALT_SIZE,
                iterations="1000",  # type: ignore[arg-type]
            )

    def test_derive_rejects_non_positive_iterations(self) -> None:
        with self.assertRaises(ValueError):
            PasswordService._derive(
                password="Correct-Horse-Battery",
                salt=b"s" * PasswordService.SALT_SIZE,
                iterations=0,
            )
