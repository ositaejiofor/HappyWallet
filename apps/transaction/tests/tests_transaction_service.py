"""
Unit tests for HappyWallet TransactionService.

TransactionService is the orchestration boundary between:

    TransactionService
        |
        +--> TransactionBuilder
        +--> TransactionDecoder
        +--> SigningService
        +--> TransactionEncoder
        +--> TransactionBroadcaster

Test policy
-----------

* No real blockchain RPC calls.
* No real private-key operations.
* No real transaction broadcasting.
* Private keys must only enter the signing stage.
* Private keys must never reach preparation, decoding, encoding,
  or broadcasting.
* Invalid signatures must stop execution before encoding/broadcasting.
* Network mismatches must fail closed.
* Empty and malformed transaction data must be rejected.
* DTOs must remain immutable.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.transaction.services.transaction_service import (
    BroadcastResult,
    PreparedTransaction,
    Signature,
    SignedTransaction,
    SigningRequest,
    TransactionBroadcastError,
    TransactionBuildError,
    TransactionService,
    TransactionSigningError,
    TransactionValidationError,
)


class TransactionServiceTests(SimpleTestCase):
    """Unit tests for TransactionService."""

    NETWORK = "ethereum"
    PRIVATE_KEY = b"\x11" * 32
    PAYLOAD = b'{"network":"ethereum","transaction_type":"transfer"}'

    DATA = {
        "network": "ethereum",
        "transaction_type": "transfer",
    }

    def setUp(self) -> None:
        self.service = TransactionService()

    # ==================================================================
    # TEST FIXTURES
    # ==================================================================

    def _signature(
        self,
        *,
        network: str = "ethereum",
    ) -> Signature:
        """Return a valid test Signature DTO."""
        return Signature(
            network=network,
            signature_der=b"signature",
            public_key=b"public",
            message_hash="message-hash",
            algorithm="secp256k1",
        )

    def _signed_transaction(
        self,
        *,
        network: str = "ethereum",
        transaction_hash: str | None = "tx-hash",
    ) -> SignedTransaction:
        """Return a valid test SignedTransaction DTO."""
        return SignedTransaction(
            network=network,
            payload=self.PAYLOAD,
            raw_transaction=b"signed-raw-transaction",
            transaction_hash=transaction_hash,
            signature=self._signature(network=network),
            metadata={},
        )

    def _prepared_transaction(
        self,
        *,
        network: str = "ethereum",
    ) -> PreparedTransaction:
        """Return a valid test PreparedTransaction DTO."""
        return PreparedTransaction(
            network=network,
            payload=self.PAYLOAD,
            payload_hash="payload-hash",
            metadata={},
        )

    def _signing_request(
        self,
        *,
        network: str = "ethereum",
    ) -> SigningRequest:
        """Return a valid test SigningRequest DTO."""
        return SigningRequest(
            network=network,
            digest=b"\x22" * 32,
            metadata={},
        )

    # ==================================================================
    # NETWORK NORMALIZATION
    # ==================================================================

    def test_normalize_network_returns_canonical_name(self) -> None:
        result = TransactionService.normalize_network("ethereum")

        self.assertEqual(result, "ethereum")

    def test_normalize_network_accepts_eth_alias(self) -> None:
        result = TransactionService.normalize_network("ETH")

        self.assertEqual(result, "ethereum")

    def test_normalize_network_accepts_btc_alias(self) -> None:
        result = TransactionService.normalize_network("BTC")

        self.assertEqual(result, "bitcoin")

    def test_normalize_network_accepts_trx_alias(self) -> None:
        result = TransactionService.normalize_network("TRX")

        self.assertEqual(result, "tron")

    def test_normalize_network_strips_whitespace(self) -> None:
        result = TransactionService.normalize_network("  Ethereum  ")

        self.assertEqual(result, "ethereum")

    def test_normalize_network_rejects_unsupported_network(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService.normalize_network("solana")

    def test_normalize_network_rejects_non_string(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService.normalize_network(None)

    # ==================================================================
    # AMOUNT VALIDATION
    # ==================================================================

    def test_validate_amount_accepts_positive_value(self) -> None:
        result = TransactionService._validate_amount("1.500")

        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal("1.500"))

    def test_validate_amount_preserves_decimal_value(self) -> None:
        result = TransactionService._validate_amount("1.500")

        self.assertEqual(str(result), "1.500")

    def test_validate_amount_accepts_integer_string(self) -> None:
        result = TransactionService._validate_amount("10")

        self.assertEqual(result, Decimal("10"))

    def test_validate_amount_rejects_invalid_value(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_amount("not-a-number")

    def test_validate_amount_rejects_empty_value(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_amount("")

    def test_validate_amount_rejects_zero(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_amount("0")

    def test_validate_amount_rejects_negative_value(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_amount("-1")

    # ==================================================================
    # BYTE VALIDATION
    # ==================================================================

    def test_validate_bytes_accepts_non_empty_bytes(self) -> None:
        result = TransactionService._validate_bytes(
            self.PAYLOAD,
            field_name="Transaction payload",
        )

        self.assertEqual(result, self.PAYLOAD)

    def test_validate_bytes_rejects_non_bytes(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_bytes(
                "payload",
                field_name="Transaction payload",
            )

    def test_validate_bytes_rejects_empty_bytes(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_bytes(
                b"",
                field_name="Transaction payload",
            )

    def test_validate_bytes_rejects_empty_private_key(self) -> None:
        with self.assertRaises(TransactionValidationError):
            TransactionService._validate_bytes(
                b"",
                field_name="Private key",
            )

    # ==================================================================
    # PAYLOAD HASH
    # ==================================================================

    def test_payload_hash_is_deterministic(self) -> None:
        first = TransactionService._payload_hash(self.PAYLOAD)
        second = TransactionService._payload_hash(self.PAYLOAD)

        self.assertEqual(first, second)

    def test_payload_hash_changes_when_payload_changes(self) -> None:
        first = TransactionService._payload_hash(self.PAYLOAD)
        second = TransactionService._payload_hash(b"different-payload")

        self.assertNotEqual(first, second)

    def test_payload_hash_is_sha256_hex(self) -> None:
        result = TransactionService._payload_hash(self.PAYLOAD)

        self.assertEqual(len(result), 64)
        self.assertRegex(result, r"^[0-9a-f]{64}$")

    # ==================================================================
    # DTO IMMUTABILITY
    # ==================================================================

    def test_prepared_transaction_is_immutable(self) -> None:
        prepared = self._prepared_transaction()

        with self.assertRaises(AttributeError):
            prepared.network = "bitcoin"

    def test_signature_is_immutable(self) -> None:
        signature = self._signature()

        with self.assertRaises(AttributeError):
            signature.network = "bitcoin"

    def test_signed_transaction_is_immutable(self) -> None:
        signed = self._signed_transaction()

        with self.assertRaises(AttributeError):
            signed.network = "bitcoin"

    def test_broadcast_result_is_immutable(self) -> None:
        result = BroadcastResult(
            network="ethereum",
            transaction_hash="0xabc",
        )

        with self.assertRaises(AttributeError):
            result.network = "bitcoin"

    def test_signing_request_is_immutable(self) -> None:
        request = self._signing_request()

        with self.assertRaises(AttributeError):
            request.network = "bitcoin"

    # ==================================================================
    # BROADCAST HASH EXTRACTION
    # ==================================================================

    def test_extract_hash_from_string(self) -> None:
        result = TransactionService._extract_broadcast_hash("0xabc")

        self.assertEqual(result, "0xabc")

    def test_extract_hash_from_transaction_hash_key(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {"transaction_hash": "0xabc"},
        )

        self.assertEqual(result, "0xabc")

    def test_extract_hash_from_tx_hash_key(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {"tx_hash": "0xabc"},
        )

        self.assertEqual(result, "0xabc")

    def test_extract_hash_from_hash_key(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {"hash": "0xabc"},
        )

        self.assertEqual(result, "0xabc")

    def test_extract_hash_from_txid_key(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {"txid": "abc"},
        )

        self.assertEqual(result, "abc")

    def test_extract_hash_from_result_key(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {"result": "0xabc"},
        )

        self.assertEqual(result, "0xabc")

    def test_extract_hash_from_object_attribute(self) -> None:
        result = SimpleNamespace(transaction_hash="0xabc")

        extracted = TransactionService._extract_broadcast_hash(result)

        self.assertEqual(extracted, "0xabc")

    def test_extract_hash_returns_none_when_missing(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {"unexpected": "value"},
        )

        self.assertIsNone(result)

    def test_extract_hash_uses_fallback(self) -> None:
        result = TransactionService._extract_broadcast_hash(
            {},
            fallback="0xfallback",
        )

        self.assertEqual(result, "0xfallback")

    # ==================================================================
    # PREPARE
    # ==================================================================

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_returns_prepared_transaction(
        self,
        mock_get_builder,
    ) -> None:
        mock_builder = MagicMock()
        mock_builder.build.return_value = self.PAYLOAD
        mock_get_builder.return_value = mock_builder

        result = self.service.prepare(
            network="ethereum",
            data=self.DATA,
        )

        self.assertIsInstance(result, PreparedTransaction)
        self.assertEqual(result.network, "ethereum")
        self.assertEqual(result.payload, self.PAYLOAD)
        self.assertEqual(
            result.payload_hash,
            TransactionService._payload_hash(self.PAYLOAD),
        )

        mock_get_builder.assert_called_once_with("ethereum")
        mock_builder.build.assert_called_once_with(
            network="ethereum",
            data=self.DATA,
        )

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_normalizes_network_before_building(
        self,
        mock_get_builder,
    ) -> None:
        mock_builder = MagicMock()
        mock_builder.build.return_value = self.PAYLOAD
        mock_get_builder.return_value = mock_builder

        result = self.service.prepare(
            network="ETH",
            data=self.DATA,
        )

        self.assertEqual(result.network, "ethereum")

        mock_get_builder.assert_called_once_with("ethereum")
        mock_builder.build.assert_called_once_with(
            network="ethereum",
            data=self.DATA,
        )

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_wraps_builder_failure(
        self,
        mock_get_builder,
    ) -> None:
        mock_builder = MagicMock()
        mock_builder.build.side_effect = RuntimeError("builder failure")
        mock_get_builder.return_value = mock_builder

        with self.assertRaises(TransactionBuildError):
            self.service.prepare(
                network="ethereum",
                data=self.DATA,
            )

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_rejects_empty_builder_payload(
        self,
        mock_get_builder,
    ) -> None:
        mock_builder = MagicMock()
        mock_builder.build.return_value = b""
        mock_get_builder.return_value = mock_builder

        with self.assertRaises(TransactionValidationError):
            self.service.prepare(
                network="ethereum",
                data=self.DATA,
            )

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_rejects_unsupported_builder_result(
        self,
        mock_get_builder,
    ) -> None:
        mock_builder = MagicMock()
        mock_builder.build.return_value = object()
        mock_get_builder.return_value = mock_builder

        with self.assertRaises(TransactionBuildError):
            self.service.prepare(
                network="ethereum",
                data=self.DATA,
            )

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_accepts_object_builder_result(
        self,
        mock_get_builder,
    ) -> None:
        builder_result = SimpleNamespace(
            payload=self.PAYLOAD,
            metadata={"source": "test"},
        )

        mock_builder = MagicMock()
        mock_builder.build.return_value = builder_result
        mock_get_builder.return_value = mock_builder

        result = self.service.prepare(
            network="ethereum",
            data=self.DATA,
        )

        self.assertEqual(result.payload, self.PAYLOAD)
        self.assertEqual(
            result.metadata,
            {"source": "test"},
        )

    @patch.object(TransactionService, "_get_builder")
    def test_prepare_accepts_dict_builder_result(
        self,
        mock_get_builder,
    ) -> None:
        mock_builder = MagicMock()
        mock_builder.build.return_value = {
            "payload": self.PAYLOAD,
            "metadata": {"source": "test"},
        }
        mock_get_builder.return_value = mock_builder

        result = self.service.prepare(
            network="ethereum",
            data=self.DATA,
        )

        self.assertEqual(result.payload, self.PAYLOAD)
        self.assertEqual(
            result.metadata,
            {"source": "test"},
        )

    # ==================================================================
    # DECODE
    # ==================================================================

    @patch.object(TransactionService, "_get_decoder")
    def test_decode_delegates_to_decoder(
        self,
        mock_get_decoder,
    ) -> None:
        expected = MagicMock()

        mock_decoder = MagicMock()
        mock_decoder.decode.return_value = expected
        mock_get_decoder.return_value = mock_decoder

        result = self.service.decode(
            network="ethereum",
            payload=self.PAYLOAD,
        )

        self.assertIs(result, expected)
        mock_get_decoder.assert_called_once_with()
        mock_decoder.decode.assert_called_once_with(
            self.PAYLOAD,
        )

    def test_decode_rejects_empty_payload(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.decode(
                network="ethereum",
                payload=b"",
            )

    def test_decode_rejects_non_bytes_payload(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.decode(
                network="ethereum",
                payload="payload",
            )

    # ==================================================================
    # SIGN
    # ==================================================================

    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    def test_sign_delegates_through_signing_boundary(
        self,
        mock_prepare_signing,
        mock_sign_request,
    ) -> None:
        signing_request = self._signing_request()
        expected = self._signature()

        mock_prepare_signing.return_value = signing_request
        mock_sign_request.return_value = expected

        result = self.service.sign(
            private_key=self.PRIVATE_KEY,
            network="ethereum",
            payload=self.PAYLOAD,
        )

        self.assertIsInstance(result, Signature)
        self.assertIs(result, expected)

        mock_prepare_signing.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            decoded=None,
        )
        mock_sign_request.assert_called_once_with(
            self.PRIVATE_KEY,
            signing_request,
        )

    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    def test_sign_normalizes_network(
        self,
        mock_prepare_signing,
        mock_sign_request,
    ) -> None:
        mock_prepare_signing.return_value = self._signing_request()
        mock_sign_request.return_value = self._signature()

        result = self.service.sign(
            private_key=self.PRIVATE_KEY,
            network="ETH",
            payload=self.PAYLOAD,
        )

        self.assertEqual(result.network, "ethereum")

        mock_prepare_signing.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            decoded=None,
        )
        mock_sign_request.assert_called_once_with(
            self.PRIVATE_KEY,
            mock_prepare_signing.return_value,
        )

    @patch("apps.transaction.services.transaction_service.SigningService")
    @patch.object(TransactionService, "prepare_signing")
    def test_sign_wraps_signing_failure(
        self,
        mock_prepare_signing,
        mock_signing_service_class,
    ) -> None:
        mock_prepare_signing.return_value = self._signing_request()

        mock_signing_service_class.return_value.sign_digest.side_effect = (
            RuntimeError("signing failure")
        )

        with self.assertRaises(TransactionSigningError):
            self.service.sign(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                payload=self.PAYLOAD,
            )

    def test_sign_rejects_empty_private_key(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.sign(
                private_key=b"",
                network="ethereum",
                payload=self.PAYLOAD,
            )

    def test_sign_rejects_non_bytes_private_key(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.sign(
                private_key="private-key",
                network="ethereum",
                payload=self.PAYLOAD,
            )

    def test_sign_rejects_empty_payload(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.sign(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                payload=b"",
            )

    def test_sign_rejects_non_bytes_payload(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.sign(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                payload="payload",
            )

    # ==================================================================
    # VERIFY
    # ==================================================================

    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "prepare_signing")
    def test_verify_delegates_through_verification_boundary(
        self,
        mock_prepare_signing,
        mock_verify_signature,
    ) -> None:
        signing_request = self._signing_request()

        mock_prepare_signing.return_value = signing_request
        mock_verify_signature.return_value = True

        result = self.service.verify(
            network="ethereum",
            payload=self.PAYLOAD,
            public_key=b"public",
            signature=b"signature",
        )

        self.assertTrue(result)

        mock_prepare_signing.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            decoded=None,
        )
        mock_verify_signature.assert_called_once_with(
            signing_request,
            b"signature",
            b"public",
        )

    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "prepare_signing")
    def test_verify_propagates_verification_failure(
        self,
        mock_prepare_signing,
        mock_verify_signature,
    ) -> None:
        mock_prepare_signing.return_value = self._signing_request()
        mock_verify_signature.side_effect = RuntimeError(
            "verification failure",
        )

        with self.assertRaises(RuntimeError):
            self.service.verify(
                network="ethereum",
                payload=self.PAYLOAD,
                public_key=b"public",
                signature=b"signature",
            )

    def test_verify_rejects_empty_payload(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.verify(
                network="ethereum",
                payload=b"",
                public_key=b"public",
                signature=b"signature",
            )

    def test_verify_rejects_non_bytes_public_key(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.verify(
                network="ethereum",
                payload=self.PAYLOAD,
                public_key="public",
                signature=b"signature",
            )

    def test_verify_rejects_empty_public_key(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.verify(
                network="ethereum",
                payload=self.PAYLOAD,
                public_key=b"",
                signature=b"signature",
            )

    def test_verify_rejects_non_bytes_signature(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.verify(
                network="ethereum",
                payload=self.PAYLOAD,
                public_key=b"public",
                signature="signature",
            )

    def test_verify_rejects_empty_signature(self) -> None:
        with self.assertRaises(TransactionValidationError):
            self.service.verify(
                network="ethereum",
                payload=self.PAYLOAD,
                public_key=b"public",
                signature=b"",
            )

    # ==================================================================
    # BROADCAST
    # ==================================================================

    @patch(
        "apps.transaction.services.transaction_service.TransactionBroadcaster",
    )
    def test_broadcast_delegates_to_broadcaster(
        self,
        mock_broadcaster_class,
    ) -> None:
        signed = self._signed_transaction()

        mock_broadcaster_class.return_value.broadcast.return_value = {
            "transaction_hash": "0xabc",
        }

        result = self.service.broadcast(
            network="ethereum",
            signed_transaction=signed,
        )

        self.assertIsInstance(result, BroadcastResult)
        self.assertEqual(result.network, "ethereum")
        self.assertEqual(result.transaction_hash, "0xabc")

        mock_broadcaster_class.return_value.broadcast.assert_called_once_with(
            network="ethereum",
            signed_transaction=signed,
        )

    def test_broadcast_rejects_network_mismatch(self) -> None:
        signed = self._signed_transaction(network="bitcoin")

        with self.assertRaises(TransactionBroadcastError):
            self.service.broadcast(
                network="ethereum",
                signed_transaction=signed,
            )

    def test_broadcast_rejects_invalid_signed_transaction_type(self) -> None:
        with self.assertRaises(TransactionBroadcastError):
            self.service.broadcast(
                network="ethereum",
                signed_transaction=object(),
            )

    @patch(
        "apps.transaction.services.transaction_service.TransactionBroadcaster",
    )
    def test_broadcast_wraps_broadcaster_failure(
        self,
        mock_broadcaster_class,
    ) -> None:
        signed = self._signed_transaction()

        mock_broadcaster_class.return_value.broadcast.side_effect = (
            RuntimeError("broadcast failure")
        )

        with self.assertRaises(TransactionBroadcastError):
            self.service.broadcast(
                network="ethereum",
                signed_transaction=signed,
            )

    @patch(
        "apps.transaction.services.transaction_service.TransactionBroadcaster",
    )
    def test_broadcast_rejects_missing_hash(
        self,
        mock_broadcaster_class,
    ) -> None:
        signed = self._signed_transaction(transaction_hash=None)

        mock_broadcaster_class.return_value.broadcast.return_value = {}

        with self.assertRaises(TransactionBroadcastError):
            self.service.broadcast(
                network="ethereum",
                signed_transaction=signed,
            )

    @patch(
        "apps.transaction.services.transaction_service.TransactionBroadcaster",
    )
    def test_broadcast_uses_signed_transaction_hash_as_fallback(
        self,
        mock_broadcaster_class,
    ) -> None:
        signed = self._signed_transaction(
            transaction_hash="0xfallback",
        )

        mock_broadcaster_class.return_value.broadcast.return_value = {}

        result = self.service.broadcast(
            network="ethereum",
            signed_transaction=signed,
        )

        self.assertEqual(
            result.transaction_hash,
            "0xfallback",
        )

    @patch(
        "apps.transaction.services.transaction_service.TransactionBroadcaster",
    )
    def test_broadcast_never_receives_private_key(
        self,
        mock_broadcaster_class,
    ) -> None:
        signed = self._signed_transaction()

        mock_broadcaster_class.return_value.broadcast.return_value = {
            "transaction_hash": "0xabc",
        }

        self.service.broadcast(
            network="ethereum",
            signed_transaction=signed,
        )

        kwargs = (
            mock_broadcaster_class
            .return_value
            .broadcast
            .call_args.kwargs
        )

        self.assertNotIn("private_key", kwargs)
        self.assertNotIn("mnemonic", kwargs)
        self.assertNotIn("secret", kwargs)

    def test_broadcast_rejects_unsupported_network_before_broadcaster(
        self,
    ) -> None:
        signed = self._signed_transaction()

        with self.assertRaises(TransactionValidationError):
            self.service.broadcast(
                network="solana",
                signed_transaction=signed,
            )

    # ==================================================================
    # EXECUTE PIPELINE
    # ==================================================================

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_runs_complete_pipeline(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        prepared = self._prepared_transaction()
        decoded = MagicMock()
        signing_request = self._signing_request()
        signature = self._signature()
        signed_transaction = self._signed_transaction()

        mock_prepare.return_value = prepared
        mock_decode.return_value = decoded
        mock_prepare_signing.return_value = signing_request
        mock_sign_request.return_value = signature
        mock_verify_signature.return_value = True
        mock_encode_signed_transaction.return_value = signed_transaction
        mock_broadcast.return_value = BroadcastResult(
            network="ethereum",
            transaction_hash="0xabc",
        )

        result = self.service.execute(
            private_key=self.PRIVATE_KEY,
            network="ethereum",
            data=self.DATA,
        )

        self.assertIsInstance(result, BroadcastResult)
        self.assertEqual(result.network, "ethereum")
        self.assertEqual(result.transaction_hash, "0xabc")

        mock_prepare.assert_called_once_with(
            "ethereum",
            self.DATA,
            metadata=None,
        )

        mock_decode.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
        )

        mock_prepare_signing.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            decoded=decoded,
        )

        mock_sign_request.assert_called_once_with(
            self.PRIVATE_KEY,
            signing_request,
        )

        mock_verify_signature.assert_called_once_with(
            signing_request,
            signature.signature_der,
            signature.public_key,
        )

        mock_encode_signed_transaction.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            signature,
            decoded=decoded,
        )

        mock_broadcast.assert_called_once_with(
            network="ethereum",
            signed_transaction=signed_transaction,
        )

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_normalizes_network_before_pipeline(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        mock_prepare.return_value = self._prepared_transaction()
        decoded = MagicMock()
        signing_request = self._signing_request()
        signature = self._signature()
        signed_transaction = self._signed_transaction()

        mock_decode.return_value = decoded
        mock_prepare_signing.return_value = signing_request
        mock_sign_request.return_value = signature
        mock_verify_signature.return_value = True
        mock_encode_signed_transaction.return_value = signed_transaction
        mock_broadcast.return_value = BroadcastResult(
            network="ethereum",
            transaction_hash="0xabc",
        )

        self.service.execute(
            private_key=self.PRIVATE_KEY,
            network="ETH",
            data=self.DATA,
        )

        mock_prepare.assert_called_once_with(
            "ethereum",
            self.DATA,
            metadata=None,
        )

        mock_decode.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
        )

        mock_prepare_signing.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            decoded=decoded,
        )

        mock_sign_request.assert_called_once_with(
            self.PRIVATE_KEY,
            signing_request,
        )

        mock_verify_signature.assert_called_once_with(
            signing_request,
            signature.signature_der,
            signature.public_key,
        )

        mock_encode_signed_transaction.assert_called_once_with(
            "ethereum",
            self.PAYLOAD,
            signature,
            decoded=decoded,
        )

        mock_broadcast.assert_called_once_with(
            network="ethereum",
            signed_transaction=signed_transaction,
        )

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_stops_before_broadcast_when_signature_invalid(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        mock_prepare.return_value = self._prepared_transaction()
        mock_decode.return_value = MagicMock()
        mock_prepare_signing.return_value = self._signing_request()
        mock_sign_request.return_value = self._signature()
        mock_verify_signature.return_value = False

        with self.assertRaises(TransactionSigningError):
            self.service.execute(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                data=self.DATA,
            )

        mock_encode_signed_transaction.assert_not_called()
        mock_broadcast.assert_not_called()

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_passes_private_key_only_to_signing_stage(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        prepared = self._prepared_transaction()
        decoded = MagicMock()
        signing_request = self._signing_request()
        signature = self._signature()
        signed_transaction = self._signed_transaction()

        mock_prepare.return_value = prepared
        mock_decode.return_value = decoded
        mock_prepare_signing.return_value = signing_request
        mock_sign_request.return_value = signature
        mock_verify_signature.return_value = True
        mock_encode_signed_transaction.return_value = signed_transaction
        mock_broadcast.return_value = BroadcastResult(
            network="ethereum",
            transaction_hash="0xabc",
        )

        self.service.execute(
            private_key=self.PRIVATE_KEY,
            network="ethereum",
            data=self.DATA,
        )

        prepare_call = mock_prepare.call_args
        decode_call = mock_decode.call_args
        signing_call = mock_sign_request.call_args
        encode_call = mock_encode_signed_transaction.call_args
        broadcast_call = mock_broadcast.call_args

        prepare_kwargs = prepare_call.kwargs
        decode_kwargs = decode_call.kwargs
        signing_kwargs = signing_call.kwargs
        encode_kwargs = encode_call.kwargs
        broadcast_kwargs = broadcast_call.kwargs

        self.assertNotIn("private_key", prepare_kwargs)
        self.assertNotIn("private_key", decode_kwargs)

        self.assertEqual(
            signing_call.args[0],
            self.PRIVATE_KEY,
        )

        self.assertNotIn(
            "private_key",
            signing_kwargs,
        )

        self.assertNotIn("private_key", encode_kwargs)

        self.assertNotIn("private_key", broadcast_kwargs)
        self.assertNotIn("mnemonic", broadcast_kwargs)
        self.assertNotIn("secret", broadcast_kwargs)

        self.assertNotIn(
            self.PRIVATE_KEY,
            encode_call.args,
        )

        self.assertNotIn(
            self.PRIVATE_KEY,
            broadcast_call.args,
        )

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_does_not_broadcast_unsigned_transaction(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        mock_prepare.return_value = self._prepared_transaction()
        mock_decode.return_value = MagicMock()
        mock_prepare_signing.return_value = self._signing_request()

        mock_sign_request.side_effect = TransactionSigningError(
            "signing failed",
        )

        with self.assertRaises(TransactionSigningError):
            self.service.execute(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                data=self.DATA,
            )

        mock_verify_signature.assert_not_called()
        mock_encode_signed_transaction.assert_not_called()
        mock_broadcast.assert_not_called()

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_stops_when_decode_fails(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        mock_prepare.return_value = self._prepared_transaction()
        mock_decode.side_effect = TransactionValidationError(
            "invalid transaction",
        )

        with self.assertRaises(TransactionValidationError):
            self.service.execute(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                data=self.DATA,
            )

        mock_prepare_signing.assert_not_called()
        mock_sign_request.assert_not_called()
        mock_verify_signature.assert_not_called()
        mock_encode_signed_transaction.assert_not_called()
        mock_broadcast.assert_not_called()

    @patch.object(TransactionService, "broadcast")
    @patch.object(TransactionService, "encode_signed_transaction")
    @patch.object(TransactionService, "_verify_signature")
    @patch.object(TransactionService, "_sign_request")
    @patch.object(TransactionService, "prepare_signing")
    @patch.object(TransactionService, "decode")
    @patch.object(TransactionService, "prepare")
    def test_execute_stops_when_prepare_fails(
        self,
        mock_prepare,
        mock_decode,
        mock_prepare_signing,
        mock_sign_request,
        mock_verify_signature,
        mock_encode_signed_transaction,
        mock_broadcast,
    ) -> None:
        mock_prepare.side_effect = TransactionBuildError(
            "unable to build transaction",
        )

        with self.assertRaises(TransactionBuildError):
            self.service.execute(
                private_key=self.PRIVATE_KEY,
                network="ethereum",
                data=self.DATA,
            )

        mock_decode.assert_not_called()
        mock_prepare_signing.assert_not_called()
        mock_sign_request.assert_not_called()
        mock_verify_signature.assert_not_called()
        mock_encode_signed_transaction.assert_not_called()
        mock_broadcast.assert_not_called()
