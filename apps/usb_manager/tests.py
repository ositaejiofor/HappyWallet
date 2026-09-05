from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from apps.security.encryption import (
    EncryptionService,
    InvalidPasswordError,
)
from apps.security.vault import WalletSecret
from apps.usb_manager.detector import USBDevice, USBDetector
from apps.usb_manager.transport import (
    InvalidTransportMessage,
    MessageType,
    TransportError,
    TransportFactory,
    TransportMessage,
    TransportRequests,
    TransportResponses,
    TransportSecurityError,
    TransportSession,
    UnsupportedMessageType,
    UnsupportedProtocolVersion,
    transaction_digest,
)
from apps.usb_manager.vault import (
    InvalidUSBVaultError,
    USBVault,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)


# ============================================================================
# USB DETECTOR
# ============================================================================


class USBDetectorTests(SimpleTestCase):

    def test_is_available_for_existing_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            device = USBDevice(
                device_id="TEST",
                mount_path=Path(temp_dir),
                removable=True,
            )

            self.assertTrue(
                USBDetector.is_available(device)
            )

    def test_is_available_for_missing_directory(self):
        device = USBDevice(
            device_id="TEST",
            mount_path=(
                Path(tempfile.gettempdir())
                / "happywallet-nonexistent-device"
            ),
            removable=True,
        )

        self.assertFalse(
            USBDetector.is_available(device)
        )

    def test_find_returns_matching_device(self):
        detector = USBDetector()

        device = USBDevice(
            device_id="USB-123",
            mount_path=Path(tempfile.gettempdir()),
            removable=True,
        )

        with mock.patch.object(
            detector,
            "detect",
            return_value=[device],
        ):
            result = detector.find("USB-123")

        self.assertEqual(
            result,
            device,
        )

    def test_find_returns_none_for_unknown_device(self):
        detector = USBDetector()

        device = USBDevice(
            device_id="USB-123",
            mount_path=Path(tempfile.gettempdir()),
            removable=True,
        )

        with mock.patch.object(
            detector,
            "detect",
            return_value=[device],
        ):
            result = detector.find("USB-999")

        self.assertIsNone(result)

    def test_detect_dispatches_windows(self):
        detector = USBDetector()

        with mock.patch.object(
            detector,
            "_detect_windows",
            return_value=[],
        ) as detect_windows:
            detector.system = "windows"

            result = detector.detect()

        detect_windows.assert_called_once_with()

        self.assertEqual(
            result,
            [],
        )

    def test_detect_dispatches_linux(self):
        detector = USBDetector()

        with mock.patch.object(
            detector,
            "_detect_linux",
            return_value=[],
        ) as detect_linux:
            detector.system = "linux"

            result = detector.detect()

        detect_linux.assert_called_once_with()

        self.assertEqual(
            result,
            [],
        )

    def test_detect_dispatches_macos(self):
        detector = USBDetector()

        with mock.patch.object(
            detector,
            "_detect_macos",
            return_value=[],
        ) as detect_macos:
            detector.system = "darwin"

            result = detector.detect()

        detect_macos.assert_called_once_with()

        self.assertEqual(
            result,
            [],
        )

    def test_detect_returns_empty_for_unsupported_system(self):
        detector = USBDetector()
        detector.system = "unknown"

        self.assertEqual(
            detector.detect(),
            [],
        )

    def test_free_space_for_existing_device(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            device = USBDevice(
                device_id="USB-SPACE",
                mount_path=Path(temp_dir),
            )

            free_space = USBDetector.free_space(device)

            self.assertIsInstance(
                free_space,
                int,
            )

            self.assertGreaterEqual(
                free_space,
                0,
            )

    def test_free_space_rejects_unavailable_device(self):
        device = USBDevice(
            device_id="USB-MISSING",
            mount_path=(
                Path(tempfile.gettempdir())
                / "happywallet-missing-space-device"
            ),
        )

        with self.assertRaises(OSError):
            USBDetector.free_space(device)


# ============================================================================
# TRANSPORT MESSAGE
# ============================================================================


class TransportMessageTests(SimpleTestCase):

    def make_message(
        self,
        *,
        payload=None,
        message_type=MessageType.HELLO,
        request_id="request-123",
        protocol="happywallet-usb",
        version=1,
        checksum=None,
    ):
        return TransportMessage(
            message_type=message_type,
            request_id=request_id,
            payload={} if payload is None else payload,
            protocol=protocol,
            version=version,
            checksum=checksum,
        )

    def test_valid_message(self):
        message = self.make_message(
            payload={
                "wallet_address": "0x123",
            }
        )

        message.validate()

    def test_empty_request_id_is_rejected(self):
        message = self.make_message(
            request_id="",
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_whitespace_request_id_is_rejected(self):
        message = self.make_message(
            request_id="   ",
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_non_string_request_id_is_rejected(self):
        message = self.make_message(
            request_id=123,
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_invalid_protocol_is_rejected(self):
        message = self.make_message(
            protocol="invalid-protocol",
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_non_integer_version_is_rejected(self):
        message = self.make_message(
            version="1",
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_boolean_version_is_rejected(self):
        message = self.make_message(
            version=True,
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_unsupported_version_is_rejected(self):
        message = self.make_message(
            version=999,
        )

        with self.assertRaises(
            UnsupportedProtocolVersion
        ):
            message.validate()

    def test_invalid_message_type_is_rejected(self):
        message = self.make_message(
            message_type="unknown",
        )

        with self.assertRaises(
            UnsupportedMessageType
        ):
            message.validate()

    def test_non_dict_payload_is_rejected(self):
        message = self.make_message(
            payload="invalid",
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            message.validate()

    def test_private_key_is_rejected(self):
        message = self.make_message(
            payload={
                "private_key": "secret",
            }
        )

        with self.assertRaises(
            TransportSecurityError
        ):
            message.validate()

    def test_mnemonic_is_rejected(self):
        message = self.make_message(
            payload={
                "wallet": {
                    "mnemonic": "secret words",
                }
            }
        )

        with self.assertRaises(
            TransportSecurityError
        ):
            message.validate()

    def test_seed_is_rejected(self):
        message = self.make_message(
            payload={
                "nested": [
                    {
                        "seed": "secret",
                    }
                ]
            }
        )

        with self.assertRaises(
            TransportSecurityError
        ):
            message.validate()

    def test_xprv_is_rejected(self):
        message = self.make_message(
            payload={
                "extended": {
                    "xprv": "secret",
                }
            }
        )

        with self.assertRaises(
            TransportSecurityError
        ):
            message.validate()

    def test_secret_key_is_rejected(self):
        message = self.make_message(
            payload={
                "secret_key": "secret",
            }
        )

        with self.assertRaises(
            TransportSecurityError
        ):
            message.validate()

    def test_nested_tuple_is_scanned(self):
        message = self.make_message(
            payload={
                "items": (
                    {
                        "master_key": "secret",
                    },
                ),
            }
        )

        with self.assertRaises(
            TransportSecurityError
        ):
            message.validate()

    def test_checksum_is_deterministic(self):
        message = self.make_message(
            payload={
                "network": "ethereum",
                "amount": "1",
            }
        )

        first = message.calculate_checksum()
        second = message.calculate_checksum()

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(first),
            64,
        )

    def test_checksum_detects_tampering(self):
        message = self.make_message(
            payload={
                "wallet_address": "0x123",
            }
        )

        serialized = message.to_dict()

        original_checksum = serialized["checksum"]

        tampered = self.make_message(
            payload={
                "wallet_address": "0x456",
            },
            checksum=original_checksum,
        )

        self.assertFalse(
            tampered.verify_checksum()
        )

    def test_missing_checksum_fails_verification(self):
        message = self.make_message()

        self.assertFalse(
            message.verify_checksum()
        )

    def test_invalid_checksum_format_fails_verification(self):
        message = self.make_message(
            checksum="not-a-checksum",
        )

        self.assertFalse(
            message.verify_checksum()
        )

    def test_json_round_trip(self):
        message = self.make_message(
            payload={
                "wallet_address": "0x123",
                "network": "ethereum",
            }
        )

        raw = message.to_json()

        restored = TransportMessage.from_json(raw)

        self.assertEqual(
            restored.message_type,
            message.message_type,
        )

        self.assertEqual(
            restored.request_id,
            message.request_id,
        )

        self.assertEqual(
            restored.payload,
            message.payload,
        )

        self.assertEqual(
            restored.checksum,
            message.calculate_checksum(),
        )

    def test_invalid_json_is_rejected(self):
        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportMessage.from_json(
                b"not-json"
            )

    def test_empty_json_is_rejected(self):
        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportMessage.from_json(
                b""
            )

    def test_missing_checksum_is_rejected(self):
        document = {
            "protocol": "happywallet-usb",
            "version": 1,
            "message_type": "hello",
            "request_id": "request-123",
            "payload": {},
        }

        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportMessage.from_dict(document)

    def test_missing_required_field_is_rejected(self):
        document = {
            "protocol": "happywallet-usb",
            "version": 1,
            "message_type": "hello",
            "request_id": "request-123",
            "checksum": "0" * 64,
        }

        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportMessage.from_dict(document)

    def test_oversized_json_is_rejected(self):
        oversized = b"x" * (
            1024 * 1024 + 1
        )

        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportMessage.from_json(
                oversized
            )


# ============================================================================
# TRANSPORT FACTORY
# ============================================================================


class TransportFactoryTests(SimpleTestCase):

    def test_request_id_is_unique(self):
        first = TransportFactory.request_id()
        second = TransportFactory.request_id()

        self.assertNotEqual(
            first,
            second,
        )

        self.assertEqual(
            len(first),
            32,
        )

    def test_create_generates_checksum(self):
        message = TransportFactory.create(
            MessageType.HELLO,
            {
                "client": "desktop",
            },
        )

        self.assertIsNotNone(
            message.checksum
        )

        self.assertTrue(
            message.verify_checksum()
        )

    def test_create_rejects_invalid_message_type(self):
        with self.assertRaises(
            UnsupportedMessageType
        ):
            TransportFactory.create(
                "invalid",
                {},
            )

    def test_create_rejects_invalid_payload(self):
        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportFactory.create(
                MessageType.HELLO,
                "invalid",
            )

    def test_create_rejects_empty_request_id(self):
        with self.assertRaises(
            InvalidTransportMessage
        ):
            TransportFactory.create(
                MessageType.HELLO,
                {},
                request_id="   ",
            )


# ============================================================================
# REQUEST BUILDERS
# ============================================================================


class TransportRequestTests(SimpleTestCase):

    def test_hello(self):
        message = TransportRequests.hello(
            "My Desktop"
        )

        self.assertEqual(
            message.message_type,
            MessageType.HELLO,
        )

        self.assertEqual(
            message.payload["device_name"],
            "My Desktop",
        )

    def test_hello_rejects_empty_device_name(self):
        with self.assertRaises(ValueError):
            TransportRequests.hello("   ")

    def test_wallet_info(self):
        message = TransportRequests.wallet_info()

        self.assertEqual(
            message.message_type,
            MessageType.WALLET_INFO_REQUEST,
        )

        self.assertEqual(
            message.payload,
            {},
        )

    def test_transaction(self):
        message = TransportRequests.transaction(
            network=" Ethereum ",
            transaction={
                "to": "0x123",
                "value": "100",
            },
        )

        self.assertEqual(
            message.message_type,
            MessageType.TRANSACTION_REQUEST,
        )

        self.assertEqual(
            message.payload["network"],
            "ethereum",
        )

    def test_transaction_rejects_empty_network(self):
        with self.assertRaises(ValueError):
            TransportRequests.transaction(
                network=" ",
                transaction={
                    "to": "0x123",
                },
            )

    def test_transaction_rejects_empty_transaction(self):
        with self.assertRaises(ValueError):
            TransportRequests.transaction(
                network="ethereum",
                transaction={},
            )

    def test_sign(self):
        message = TransportRequests.sign(
            network=" Ethereum ",
            transaction_hash=" 0xabc ",
        )

        self.assertEqual(
            message.message_type,
            MessageType.SIGN_REQUEST,
        )

        self.assertEqual(
            message.payload["network"],
            "ethereum",
        )

        self.assertEqual(
            message.payload["transaction_hash"],
            "0xabc",
        )

    def test_sign_rejects_empty_hash(self):
        with self.assertRaises(ValueError):
            TransportRequests.sign(
                network="ethereum",
                transaction_hash=" ",
            )


# ============================================================================
# RESPONSE BUILDERS
# ============================================================================


class TransportResponseTests(SimpleTestCase):

    def test_ack(self):
        message = TransportResponses.ack(
            "request-123",
            message="Accepted",
        )

        self.assertEqual(
            message.message_type,
            MessageType.ACK,
        )

        self.assertEqual(
            message.request_id,
            "request-123",
        )

    def test_device_info(self):
        message = TransportResponses.device_info(
            "request-123",
            device_id="USB-123",
            firmware_version="1.0.0",
        )

        self.assertEqual(
            message.message_type,
            MessageType.DEVICE_INFO,
        )

        self.assertEqual(
            message.payload["device_id"],
            "USB-123",
        )

    def test_wallet_info(self):
        message = TransportResponses.wallet_info(
            "request-123",
            wallet_name="Test Wallet",
            network="ethereum",
            addresses=["0x123"],
        )

        self.assertEqual(
            message.message_type,
            MessageType.WALLET_INFO_RESPONSE,
        )

        self.assertEqual(
            message.payload["addresses"],
            ["0x123"],
        )

    def test_transaction_review(self):
        message = TransportResponses.transaction_review(
            "request-123",
            network="ethereum",
            recipient="0x123",
            amount="1",
            asset="ETH",
            fee="0.001",
        )

        self.assertEqual(
            message.message_type,
            MessageType.TRANSACTION_REVIEW,
        )

        self.assertEqual(
            message.payload["fee"],
            "0.001",
        )

    def test_transaction_review_without_fee(self):
        message = TransportResponses.transaction_review(
            "request-123",
            network="ethereum",
            recipient="0x123",
            amount="1",
            asset="ETH",
        )

        self.assertNotIn(
            "fee",
            message.payload,
        )

    def test_sign_response(self):
        message = TransportResponses.sign(
            "request-123",
            network="ethereum",
            transaction_hash="0xabc",
            signature="0xsig",
        )

        self.assertEqual(
            message.message_type,
            MessageType.SIGN_RESPONSE,
        )

        self.assertEqual(
            message.payload["signature"],
            "0xsig",
        )

    def test_error_response(self):
        message = TransportResponses.error(
            "request-123",
            code="INVALID_TRANSACTION",
            message="Transaction rejected.",
        )

        self.assertEqual(
            message.message_type,
            MessageType.ERROR,
        )

        self.assertEqual(
            message.payload["code"],
            "INVALID_TRANSACTION",
        )


# ============================================================================
# TRANSPORT SESSION
# ============================================================================


class TransportSessionTests(SimpleTestCase):

    def test_desktop_session(self):
        session = TransportSession(
            role="desktop"
        )

        self.assertEqual(
            session.role,
            "desktop",
        )

        self.assertFalse(
            session.closed
        )

    def test_signer_session(self):
        session = TransportSession(
            role="signer"
        )

        self.assertEqual(
            session.role,
            "signer",
        )

    def test_invalid_role_is_rejected(self):
        with self.assertRaises(ValueError):
            TransportSession(
                role="unknown"
            )

    def test_non_string_role_is_rejected(self):
        with self.assertRaises(TypeError):
            TransportSession(
                role=123
            )

    def test_prepare_and_receive(self):
        session = TransportSession(
            role="desktop"
        )

        message = TransportRequests.hello()

        raw = session.prepare(
            message
        )

        received = session.receive(
            raw
        )

        self.assertEqual(
            received.message_type,
            MessageType.HELLO,
        )

    def test_duplicate_request_id_is_rejected(self):
        session = TransportSession(
            role="desktop"
        )

        message = TransportRequests.hello()

        session.prepare(
            message
        )

        with self.assertRaises(
            TransportError
        ):
            session.prepare(
                message
            )

    def test_closed_session_rejects_prepare(self):
        session = TransportSession(
            role="desktop"
        )

        session.close()

        with self.assertRaises(
            TransportError
        ):
            session.prepare(
                TransportRequests.hello()
            )

    def test_closed_session_rejects_receive(self):
        session = TransportSession(
            role="desktop"
        )

        session.close()

        with self.assertRaises(
            TransportError
        ):
            session.receive(
                b"{}"
            )

    def test_close_clears_state(self):
        session = TransportSession(
            role="desktop"
        )

        message = TransportRequests.hello()

        session.prepare(
            message
        )

        session.close()

        self.assertTrue(
            session.closed
        )


# ============================================================================
# TRANSACTION DIGEST
# ============================================================================


class TransactionDigestTests(SimpleTestCase):

    def test_digest_is_deterministic(self):
        transaction = {
            "to": "0x123",
            "value": "100",
            "nonce": 1,
        }

        first = transaction_digest(
            transaction
        )

        second = transaction_digest(
            transaction
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(first),
            64,
        )

    def test_digest_is_order_independent(self):
        first = transaction_digest(
            {
                "to": "0x123",
                "value": "100",
            }
        )

        second = transaction_digest(
            {
                "value": "100",
                "to": "0x123",
            }
        )

        self.assertEqual(
            first,
            second,
        )

    def test_digest_changes_when_transaction_changes(self):
        first = transaction_digest(
            {
                "to": "0x123",
                "value": "100",
            }
        )

        second = transaction_digest(
            {
                "to": "0x456",
                "value": "100",
            }
        )

        self.assertNotEqual(
            first,
            second,
        )

    def test_digest_rejects_non_dict(self):
        with self.assertRaises(TypeError):
            transaction_digest(
                "invalid"
            )

    def test_digest_rejects_empty_transaction(self):
        with self.assertRaises(ValueError):
            transaction_digest({})

    def test_digest_rejects_private_key_material(self):
        with self.assertRaises(
            TransportSecurityError
        ):
            transaction_digest(
                {
                    "to": "0x123",
                    "private_key": "secret",
                }
            )


# ============================================================================
# USB VAULT
# ============================================================================


class USBVaultTests(SimpleTestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.device = USBDevice(
            device_id="USB-TEST",
            mount_path=Path(
                self.temp_dir.name
            ),
            removable=True,
        )

        self.encryption = EncryptionService(
            n=2**12,
            r=8,
            p=1,
        )

        self.vault = USBVault(
            device=self.device,
            encryption=self.encryption,
        )

        self.secret = WalletSecret(
            mnemonic=(
                "abandon abandon abandon abandon "
                "abandon abandon abandon abandon "
                "abandon abandon abandon about"
            )
        )

        self.password = (
            "Correct-HappyWallet-Password"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_usb_is_available(self):
        self.assertTrue(
            self.vault.is_available()
        )

    def test_create_vault(self):
        metadata = self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        self.assertTrue(
            self.vault.exists()
        )

        self.assertTrue(
            self.vault.metadata_path.is_file()
        )

        self.assertEqual(
            metadata.wallet_name,
            "Test Wallet",
        )

        self.assertEqual(
            metadata.network,
            "ethereum",
        )

    def test_existing_vault_is_not_overwritten(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        with self.assertRaises(
            VaultAlreadyExistsError
        ):
            self.vault.create(
                secret=self.secret,
                password=self.password,
                wallet_name="Another Wallet",
                network="ethereum",
            )

    def test_partial_vault_is_not_overwritten(self):
        self.vault.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.vault.metadata_path.write_text(
            "{}",
            encoding="utf-8",
        )

        with self.assertRaises(
            VaultAlreadyExistsError
        ):
            self.vault.create(
                secret=self.secret,
                password=self.password,
                wallet_name="Test Wallet",
                network="ethereum",
            )

    def test_unlock_with_correct_password(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        unlocked = self.vault.unlock(
            self.password
        )

        self.assertEqual(
            unlocked.mnemonic,
            self.secret.mnemonic,
        )

    def test_wrong_password_is_rejected(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.vault.unlock(
                "Wrong-HappyWallet-Password"
            )

    def test_metadata_can_be_read(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        metadata = self.vault.read_metadata()

        self.assertEqual(
            metadata.wallet_name,
            "Test Wallet",
        )

        self.assertEqual(
            metadata.network,
            "ethereum",
        )

    def test_metadata_tampering_breaks_unlock(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        metadata = json.loads(
            self.vault.metadata_path.read_text(
                encoding="utf-8"
            )
        )

        metadata["network"] = "bitcoin"

        self.vault.metadata_path.write_text(
            json.dumps(metadata),
            encoding="utf-8",
        )

        with self.assertRaises(
            InvalidPasswordError
        ):
            self.vault.unlock(
                self.password
            )

    def test_invalid_metadata_json_is_rejected(self):
        self.vault.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.vault.metadata_path.write_text(
            "{invalid-json",
            encoding="utf-8",
        )

        with self.assertRaises(
            InvalidUSBVaultError
        ):
            self.vault.read_metadata()

    def test_missing_metadata_is_rejected(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        self.vault.metadata_path.unlink()

        with self.assertRaises(
            VaultNotFoundError
        ):
            self.vault.read_metadata()

    def test_remove_vault(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        self.vault.remove_vault()

        self.assertFalse(
            self.vault.exists()
        )

        self.assertFalse(
            self.vault.metadata_path.exists()
        )

    def test_unlock_missing_vault(self):
        with self.assertRaises(
            VaultNotFoundError
        ):
            self.vault.unlock(
                self.password
            )

    def test_empty_wallet_name_is_rejected(self):
        with self.assertRaises(ValueError):
            self.vault.create(
                secret=self.secret,
                password=self.password,
                wallet_name="   ",
                network="ethereum",
            )

    def test_empty_network_is_rejected(self):
        with self.assertRaises(ValueError):
            self.vault.create(
                secret=self.secret,
                password=self.password,
                wallet_name="Test Wallet",
                network="   ",
            )

    def test_information_returns_safe_metadata(self):
        self.vault.create(
            secret=self.secret,
            password=self.password,
            wallet_name="Test Wallet",
            network="ethereum",
        )

        info = self.vault.information()

        self.assertEqual(
            info["device_id"],
            "USB-TEST",
        )

        self.assertEqual(
            info["wallet_name"],
            "Test Wallet",
        )

        self.assertEqual(
            info["network"],
            "ethereum",
        )

        self.assertNotIn(
            "mnemonic",
            info,
        )

        self.assertNotIn(
            "private_key",
            info,
        )
