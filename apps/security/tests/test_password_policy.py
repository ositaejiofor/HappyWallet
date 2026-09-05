"""
Tests for HappyWallet password and PIN policy.

These tests intentionally test policy independently from PasswordService.

Coverage:
    - PasswordPolicy configuration
    - PinPolicy configuration
    - Password validation
    - PIN validation
    - Password complexity rules
    - Non-raising policy checks
    - Immutable policy/result objects
    - Invalid policy configuration
"""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from apps.security.password_policy import (
    CredentialType,
    InvalidPasswordPolicyError,
    InvalidPinPolicyError,
    PasswordPolicy,
    PasswordPolicyError,
    PasswordPolicyService,
    PinPolicy,
    PolicyResult,
)


# ============================================================================
# PASSWORD POLICY CONFIGURATION
# ============================================================================


class PasswordPolicyConfigurationTests(unittest.TestCase):
    """Tests for PasswordPolicy configuration."""

    def test_default_policy_values(self) -> None:
        policy = PasswordPolicy()

        self.assertEqual(policy.min_length, 12)
        self.assertEqual(policy.max_length, 1024)
        self.assertTrue(policy.require_non_empty)

        self.assertFalse(policy.require_uppercase)
        self.assertFalse(policy.require_lowercase)
        self.assertFalse(policy.require_digit)
        self.assertFalse(policy.require_special)

    def test_policy_is_immutable(self) -> None:
        policy = PasswordPolicy()

        with self.assertRaises(FrozenInstanceError):
            policy.min_length = 20  # type: ignore[misc]

    def test_minimum_length_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            PasswordPolicy(min_length=0)

    def test_maximum_length_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            PasswordPolicy(max_length=0)

    def test_minimum_cannot_exceed_maximum(self) -> None:
        with self.assertRaises(ValueError):
            PasswordPolicy(
                min_length=20,
                max_length=10,
            )

    def test_minimum_length_must_be_integer(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicy(min_length="12")  # type: ignore[arg-type]

    def test_maximum_length_must_be_integer(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicy(max_length="1024")  # type: ignore[arg-type]

    def test_complexity_options_must_be_boolean(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicy(
                require_digit=1,  # type: ignore[arg-type]
            )


# ============================================================================
# PIN POLICY CONFIGURATION
# ============================================================================


class PinPolicyConfigurationTests(unittest.TestCase):
    """Tests for PinPolicy configuration."""

    def test_default_policy_values(self) -> None:
        policy = PinPolicy()

        self.assertEqual(policy.min_length, 6)
        self.assertEqual(policy.max_length, 12)
        self.assertTrue(policy.ascii_digits_only)

    def test_policy_is_immutable(self) -> None:
        policy = PinPolicy()

        with self.assertRaises(FrozenInstanceError):
            policy.min_length = 8  # type: ignore[misc]

    def test_minimum_length_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            PinPolicy(min_length=0)

    def test_maximum_length_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            PinPolicy(max_length=0)

    def test_minimum_cannot_exceed_maximum(self) -> None:
        with self.assertRaises(ValueError):
            PinPolicy(
                min_length=12,
                max_length=6,
            )

    def test_minimum_length_must_be_integer(self) -> None:
        with self.assertRaises(TypeError):
            PinPolicy(min_length="6")  # type: ignore[arg-type]

    def test_maximum_length_must_be_integer(self) -> None:
        with self.assertRaises(TypeError):
            PinPolicy(max_length="12")  # type: ignore[arg-type]

    def test_ascii_digits_only_must_be_boolean(self) -> None:
        with self.assertRaises(TypeError):
            PinPolicy(
                ascii_digits_only=1,  # type: ignore[arg-type]
            )


# ============================================================================
# PASSWORD VALIDATION
# ============================================================================


class PasswordValidationTests(unittest.TestCase):
    """Tests for password validation."""

    def test_valid_password_is_accepted(self) -> None:
        PasswordPolicyService.validate_password(
            "correct horse battery"
        )

    def test_exact_minimum_length_is_accepted(self) -> None:
        password = "a" * 12

        PasswordPolicyService.validate_password(password)

    def test_exact_maximum_length_is_accepted(self) -> None:
        password = "a" * 1024

        PasswordPolicyService.validate_password(password)

    def test_empty_password_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password("")

    def test_short_password_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password("a" * 11)

    def test_long_password_is_rejected(self) -> None:
        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password("a" * 1025)

    def test_non_string_password_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicyService.validate_password(
                123456789012  # type: ignore[arg-type]
            )

    def test_unicode_password_is_allowed(self) -> None:
        PasswordPolicyService.validate_password(
            "correct-horse-密码-安全"
        )

    def test_whitespace_is_not_automatically_removed(self) -> None:
        PasswordPolicyService.validate_password(
            "password with intentional spaces"
        )

    def test_custom_password_policy_is_respected(self) -> None:
        policy = PasswordPolicy(
            min_length=8,
            max_length=20,
        )

        PasswordPolicyService.validate_password(
            "abcdefgh",
            policy=policy,
        )

    def test_custom_policy_can_reject_default_valid_password(self) -> None:
        policy = PasswordPolicy(
            min_length=20,
            max_length=30,
        )

        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password(
                "a" * 12,
                policy=policy,
            )


# ============================================================================
# PASSWORD COMPLEXITY
# ============================================================================


class PasswordComplexityTests(unittest.TestCase):
    """Tests for optional password complexity requirements."""

    def test_uppercase_requirement(self) -> None:
        policy = PasswordPolicy(
            require_uppercase=True,
        )

        PasswordPolicyService.validate_password(
            "Password with uppercase",
            policy=policy,
        )

    def test_missing_uppercase_is_rejected(self) -> None:
        policy = PasswordPolicy(
            require_uppercase=True,
        )

        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password(
                "password without uppercase",
                policy=policy,
            )

    def test_lowercase_requirement(self) -> None:
        policy = PasswordPolicy(
            require_lowercase=True,
        )

        PasswordPolicyService.validate_password(
            "PASSWORD with lowercase",
            policy=policy,
        )

    def test_missing_lowercase_is_rejected(self) -> None:
        policy = PasswordPolicy(
            require_lowercase=True,
        )

        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password(
                "PASSWORD ONLY",
                policy=policy,
            )

    def test_digit_requirement(self) -> None:
        policy = PasswordPolicy(
            require_digit=True,
        )

        PasswordPolicyService.validate_password(
            "password with digit 7",
            policy=policy,
        )

    def test_missing_digit_is_rejected(self) -> None:
        policy = PasswordPolicy(
            require_digit=True,
        )

        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password(
                "password without digit",
                policy=policy,
            )

    def test_special_character_requirement(self) -> None:
        policy = PasswordPolicy(
            require_special=True,
        )

        PasswordPolicyService.validate_password(
            "password with special!",
            policy=policy,
        )

    def test_missing_special_character_is_rejected(self) -> None:
        policy = PasswordPolicy(
            require_special=True,
        )

        with self.assertRaises(InvalidPasswordPolicyError):
            PasswordPolicyService.validate_password(
                "password without special",
                policy=policy,
            )

    def test_all_complexity_requirements(self) -> None:
        policy = PasswordPolicy(
            min_length=12,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
        )

        PasswordPolicyService.validate_password(
            "SecurePassword7!",
            policy=policy,
        )


# ============================================================================
# PASSWORD CHECK RESULT
# ============================================================================


class PasswordCheckTests(unittest.TestCase):
    """Tests for non-raising password checks."""

    def test_valid_password_returns_success(self) -> None:
        result = PasswordPolicyService.check_password(
            "correct horse battery"
        )

        self.assertTrue(result.valid)
        self.assertEqual(
            result.credential_type,
            CredentialType.PASSWORD,
        )
        self.assertIsNone(result.reason)

    def test_invalid_password_returns_failure(self) -> None:
        result = PasswordPolicyService.check_password(
            "short"
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.credential_type,
            CredentialType.PASSWORD,
        )
        self.assertIsNotNone(result.reason)

    def test_invalid_password_does_not_raise_policy_exception(self) -> None:
        result = PasswordPolicyService.check_password(
            "short"
        )

        self.assertFalse(result.valid)

    def test_type_error_remains_an_api_error(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicyService.check_password(
                123456789012  # type: ignore[arg-type]
            )


# ============================================================================
# PIN VALIDATION
# ============================================================================


class PinValidationTests(unittest.TestCase):
    """Tests for wallet PIN validation."""

    def test_valid_six_digit_pin_is_accepted(self) -> None:
        PasswordPolicyService.validate_pin("123456")

    def test_valid_twelve_digit_pin_is_accepted(self) -> None:
        PasswordPolicyService.validate_pin("123456789012")

    def test_short_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("12345")

    def test_long_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("1234567890123")

    def test_empty_pin_is_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("")

    def test_non_string_pin_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicyService.validate_pin(
                123456  # type: ignore[arg-type]
            )

    def test_letters_are_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("12345a")

    def test_symbols_are_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("12345!")

    def test_spaces_are_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("123 456")

    def test_unicode_digits_are_rejected(self) -> None:
        with self.assertRaises(InvalidPinPolicyError):
            PasswordPolicyService.validate_pin("１２３４５６")

    def test_ascii_digit_policy_can_be_customized(self) -> None:
        policy = PinPolicy(
            min_length=4,
            max_length=8,
            ascii_digits_only=False,
        )

        PasswordPolicyService.validate_pin(
            "１２３４",
            policy=policy,
        )

    def test_custom_pin_policy_is_respected(self) -> None:
        policy = PinPolicy(
            min_length=8,
            max_length=8,
        )

        PasswordPolicyService.validate_pin(
            "12345678",
            policy=policy,
        )


# ============================================================================
# PIN CHECK RESULT
# ============================================================================


class PinCheckTests(unittest.TestCase):
    """Tests for non-raising PIN checks."""

    def test_valid_pin_returns_success(self) -> None:
        result = PasswordPolicyService.check_pin(
            "123456"
        )

        self.assertTrue(result.valid)
        self.assertEqual(
            result.credential_type,
            CredentialType.PIN,
        )
        self.assertIsNone(result.reason)

    def test_invalid_pin_returns_failure(self) -> None:
        result = PasswordPolicyService.check_pin(
            "123"
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.credential_type,
            CredentialType.PIN,
        )
        self.assertIsNotNone(result.reason)

    def test_type_error_remains_an_api_error(self) -> None:
        with self.assertRaises(TypeError):
            PasswordPolicyService.check_pin(
                123456  # type: ignore[arg-type]
            )


# ============================================================================
# POLICY RESULT
# ============================================================================


class PolicyResultTests(unittest.TestCase):
    """Tests for PolicyResult."""

    def test_success_factory(self) -> None:
        result = PolicyResult.success(
            CredentialType.PASSWORD
        )

        self.assertTrue(result.valid)
        self.assertEqual(
            result.credential_type,
            CredentialType.PASSWORD,
        )
        self.assertIsNone(result.reason)

    def test_failure_factory(self) -> None:
        result = PolicyResult.failure(
            CredentialType.PIN,
            "PIN is too short.",
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.credential_type,
            CredentialType.PIN,
        )
        self.assertEqual(
            result.reason,
            "PIN is too short.",
        )

    def test_result_is_immutable(self) -> None:
        result = PolicyResult.success(
            CredentialType.PASSWORD
        )

        with self.assertRaises(FrozenInstanceError):
            result.valid = False  # type: ignore[misc]


# ============================================================================
# DEFAULT SERVICE CONFIGURATION
# ============================================================================


class DefaultPolicyServiceTests(unittest.TestCase):
    """Tests for PasswordPolicyService defaults."""

    def test_default_password_policy_is_available(self) -> None:
        policy = PasswordPolicyService.DEFAULT_PASSWORD_POLICY

        self.assertIsInstance(
            policy,
            PasswordPolicy,
        )

    def test_default_pin_policy_is_available(self) -> None:
        policy = PasswordPolicyService.DEFAULT_PIN_POLICY

        self.assertIsInstance(
            policy,
            PinPolicy,
        )

    def test_special_character_collection_is_immutable(self) -> None:
        characters = PasswordPolicyService.SPECIAL_CHARACTERS

        self.assertIsInstance(
            characters,
            frozenset,
        )


# ============================================================================
# EXCEPTION HIERARCHY
# ============================================================================


class ExceptionHierarchyTests(unittest.TestCase):
    """Tests for policy exception hierarchy."""

    def test_password_policy_error_is_base_exception(self) -> None:
        self.assertTrue(
            issubclass(
                InvalidPasswordPolicyError,
                PasswordPolicyError,
            )
        )

    def test_pin_policy_error_is_base_value_error(self) -> None:
        self.assertTrue(
            issubclass(
                InvalidPinPolicyError,
                PasswordPolicyError,
            )
        )

    def test_password_policy_error_is_value_error(self) -> None:
        self.assertTrue(
            issubclass(
                PasswordPolicyError,
                ValueError,
            )
        )


# ============================================================================
# ENUM TESTS
# ============================================================================


class CredentialTypeTests(unittest.TestCase):
    """Tests for CredentialType."""

    def test_password_value(self) -> None:
        self.assertEqual(
            CredentialType.PASSWORD.value,
            "password",
        )

    def test_pin_value(self) -> None:
        self.assertEqual(
            CredentialType.PIN.value,
            "pin",
        )

    def test_string_compatibility(self) -> None:
        self.assertEqual(
            CredentialType.PASSWORD,
            "password",
        )

        self.assertEqual(
            CredentialType.PIN,
            "pin",
        )


# ============================================================================
# TEST ENTRY POINT
# ============================================================================


if __name__ == "__main__":
    unittest.main()