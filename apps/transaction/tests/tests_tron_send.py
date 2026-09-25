"""Mocked safety tests for guarded TRON construction/signing/broadcast."""

import hashlib
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from datetime import timedelta
import uuid

from apps.security.vault import WalletSecret
from apps.blockchain.models import BlockchainNetwork
from apps.transaction.models import TronSendIntent
from apps.wallet.models import Wallet
from apps.transaction.services.tron_send import (
    TronBroadcastBlocked,
    TronBroadcastUnknown,
    TronResponseError,
    TronSendClient,
    TronValidationError,
    private_key_to_address,
    tron_address_to_hex,
)


PRIVATE_KEY = bytes.fromhex("11" * 32)
SENDER = private_key_to_address(PRIVATE_KEY)
RECIPIENT = private_key_to_address(bytes.fromhex("22" * 32))


class TronSendCryptoTests(SimpleTestCase):
    def test_base58check_address_validation_rejects_tampering(self):
        self.assertTrue(tron_address_to_hex(SENDER).startswith("41"))
        replacement = "1" if SENDER[-1] != "1" else "2"
        with self.assertRaises(TronValidationError):
            tron_address_to_hex(SENDER[:-1] + replacement)

    def test_signs_txid_without_persisting_or_mutating_unsigned_payload(self):
        raw_hex = "00"
        txid = hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest()
        unsigned = {"txID": txid, "raw_data_hex": raw_hex, "raw_data": {}}
        signed = TronSendClient(rpc_url="https://api.shasta.trongrid.io").sign(
            unsigned,
            WalletSecret(private_key=PRIVATE_KEY.hex()),
            SENDER,
        )
        self.assertNotIn("signature", unsigned)
        self.assertEqual(len(signed["signature"][0]), 130)

    def test_wrong_usb_key_cannot_sign_for_sender(self):
        raw_hex = "00"
        unsigned = {
            "txID": hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest(),
            "raw_data_hex": raw_hex,
        }
        with self.assertRaisesMessage(TronValidationError, "does not control"):
            TronSendClient(rpc_url="https://api.shasta.trongrid.io").sign(
                unsigned,
                WalletSecret(private_key=("33" * 32)),
                SENDER,
            )


class TronSendProviderTests(SimpleTestCase):
    def setUp(self):
        self.client = TronSendClient(rpc_url="https://api.shasta.trongrid.io")

    @patch.object(TronSendClient, "get_trx_balance", return_value=Decimal("20"))
    @patch.object(TronSendClient, "_post")
    def test_constructs_unsigned_trx_after_balance_validation(self, post, _balance):
        raw_hex = "00"
        raw_data = {
            "contract": [{
                "type": "TransferContract",
                "parameter": {"value": {
                    "owner_address": SENDER,
                    "to_address": RECIPIENT,
                    "amount": 2500000,
                }},
            }],
        }
        post.return_value = {
            "txID": hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest(),
            "raw_data_hex": raw_hex,
            "raw_data": raw_data,
        }
        prepared = self.client.prepare(
            sender=SENDER,
            recipient=RECIPIENT,
            asset="TRX",
            amount=Decimal("2.5"),
        )
        self.assertEqual(prepared.amount, Decimal("2.5"))
        self.assertEqual(post.call_args.args[0], "/wallet/createtransaction")

    @patch.object(TronSendClient, "get_trx_balance", return_value=Decimal("20"))
    @patch.object(TronSendClient, "_post")
    def test_rejects_provider_transaction_with_changed_recipient(self, post, _balance):
        raw_hex = "00"
        post.return_value = {
            "txID": hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest(),
            "raw_data_hex": raw_hex,
            "raw_data": {"contract": [{
                "type": "TransferContract",
                "parameter": {"value": {
                    "owner_address": SENDER,
                    "to_address": SENDER,
                    "amount": 2500000,
                }},
            }]},
        }
        with self.assertRaisesMessage(TronResponseError, "does not match"):
            self.client.prepare(
                sender=SENDER,
                recipient=RECIPIENT,
                asset="TRX",
                amount=Decimal("2.5"),
            )

    @override_settings(TRON_MAINNET_BROADCAST_ENABLED=False)
    def test_mainnet_broadcast_fails_before_network_call(self):
        with patch.object(self.client, "_post") as post:
            with self.assertRaises(TronBroadcastBlocked):
                self.client.broadcast({"txID": "a" * 64}, is_testnet=False)
            post.assert_not_called()

    @override_settings(TRON_TESTNET_BROADCAST_ENABLED=True)
    def test_testnet_broadcast_is_enabled(self):
        with patch.object(self.client, "_post", return_value={"result": True}) as post:
            txid = self.client.broadcast({"txID": "a" * 64}, is_testnet=True)
        self.assertEqual(txid, "a" * 64)
        post.assert_called_once()


class TronSendIdempotencyTests(TestCase):
    def test_user_idempotency_key_is_unique(self):
        user = get_user_model().objects.create_user(
            username="sender",
            email="sender@example.com",
            password="not-a-real-wallet-password",
        )
        network = BlockchainNetwork.objects.create(
            name="TRON Shasta Testnet",
            slug="tron-shasta-testnet",
            symbol="TRX",
            is_testnet=True,
        )
        wallet = Wallet.objects.create(user=user, network=network, status=Wallet.Status.ACTIVE)
        key = uuid.uuid4()
        values = dict(
            user=user,
            wallet=wallet,
            network=network,
            idempotency_key=key,
            asset="TRX",
            sender=SENDER,
            recipient=RECIPIENT,
            amount=Decimal("1"),
            estimated_fee_trx=Decimal("1.1"),
            estimated_energy=0,
            unsigned_transaction={"txID": "a" * 64},
            expires_at=timezone.now() + timedelta(minutes=1),
        )
        TronSendIntent.objects.create(**values)
        with self.assertRaises(IntegrityError), transaction.atomic():
            TronSendIntent.objects.create(**values)

    @override_settings(TRON_TESTNET_BROADCAST_ENABLED=True)
    def test_transport_failure_is_unknown_and_never_retried_by_service(self):
        client = TronSendClient(rpc_url="https://api.shasta.trongrid.io")
        with patch.object(client, "_post", side_effect=TimeoutError) as post:
            with self.assertRaises(TronBroadcastUnknown):
                client.broadcast({"txID": "a" * 64}, is_testnet=True)
        post.assert_called_once()
