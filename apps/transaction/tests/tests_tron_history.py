"""Mocked tests for public, read-only TRON transaction history."""

from __future__ import annotations

import json
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from apps.transaction.services import history as history_service
from apps.transaction.services.history import get_wallet_transaction_history
from apps.transaction.services.networks import tron
from apps.transaction.services.networks.tron import (
    TronReadOnlyClient,
    TronTransaction,
    TronTransactionHistory,
)


class _Response:
    status = 200

    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


class TronNetworkHistoryTests(SimpleTestCase):
    ADDRESS = "TUoHaVjx7n5xz8LwPRDckgFrDWhMhuSuJM"
    USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

    @patch.object(tron, "urlopen")
    def test_confirmed_trx_transfer_is_parsed(self, mock_urlopen: Mock) -> None:
        mock_urlopen.return_value = _Response(
            {
                "success": True,
                "data": [
                    {
                        "txID": "a" * 64,
                        "blockNumber": 86466249,
                        "block_timestamp": 1_700_000_000_000,
                        "ret": [{"contractRet": "SUCCESS"}],
                        "raw_data": {
                            "contract": [
                                {
                                    "type": "TransferContract",
                                    "parameter": {
                                        "value": {"amount": 1_500_000}
                                    },
                                }
                            ]
                        },
                    }
                ],
            }
        )

        result = TronReadOnlyClient(
            rpc_url="https://api.example.invalid",
            api_key="test-key",
            max_retries=0,
        ).get_transaction_history(self.ADDRESS, limit=25)

        transaction = result.transactions[0]
        self.assertTrue(result.available)
        self.assertEqual(transaction.amount, Decimal("1.5"))
        self.assertEqual(transaction.symbol, "TRX")
        self.assertEqual(transaction.status, "confirmed")
        self.assertEqual(transaction.timestamp, 1_700_000_000)

        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("only_confirmed=true", request.full_url)
        self.assertEqual(
            request.headers["Tron-pro-api-key"],
            "test-key",
        )

    @patch.object(tron, "urlopen")
    def test_non_native_contract_is_ignored(self, mock_urlopen: Mock) -> None:
        mock_urlopen.return_value = _Response(
            {
                "success": True,
                "data": [
                    {
                        "txID": "b" * 64,
                        "raw_data": {
                            "contract": [{"type": "TriggerSmartContract"}]
                        },
                    }
                ],
            }
        )

        result = TronReadOnlyClient(
            rpc_url="https://api.example.invalid",
            max_retries=0,
        ).get_transaction_history(self.ADDRESS)

        self.assertEqual(result.transactions, ())

    @patch.object(tron, "urlopen")
    def test_usdt_balance_is_read_from_confirmed_account_data(
        self,
        mock_urlopen: Mock,
    ) -> None:
        mock_urlopen.return_value = _Response(
            {
                "success": True,
                "data": [{"trc20": [{self.USDT: "9876543"}]}],
            }
        )

        balance = TronReadOnlyClient(
            rpc_url="https://api.example.invalid",
            max_retries=0,
        ).get_trc20_balance(
            self.ADDRESS,
            contract_address=self.USDT,
            decimals=6,
        )

        self.assertEqual(balance, Decimal("9.876543"))
        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertIn("only_confirmed=true", request.full_url)

    @patch.object(tron, "urlopen")
    def test_confirmed_usdt_receive_is_parsed(
        self,
        mock_urlopen: Mock,
    ) -> None:
        mock_urlopen.return_value = _Response(
            {
                "success": True,
                "data": [
                    {
                        "transaction_id": "d" * 64,
                        "token_info": {
                            "address": self.USDT,
                            "symbol": "USDT",
                            "decimals": 6,
                        },
                        "from": "TXVi4XhETj3sVhjnFQHEfZJYHqT7pW8w9M",
                        "to": self.ADDRESS,
                        "value": "2500000",
                        "block_timestamp": 1_700_000_123_000,
                    }
                ],
            }
        )

        result = TronReadOnlyClient(
            rpc_url="https://api.example.invalid",
            max_retries=0,
        ).get_trc20_transaction_history(
            self.ADDRESS,
            contract_address=self.USDT,
            symbol="USDT",
            decimals=6,
        )

        transaction = result.transactions[0]
        self.assertEqual(transaction.transaction_type, "receive")
        self.assertEqual(transaction.amount, Decimal("2.5"))
        self.assertEqual(transaction.symbol, "USDT")
        self.assertEqual(transaction.status, "confirmed")
        request = mock_urlopen.call_args.args[0]
        self.assertIn("transactions/trc20", request.full_url)
        self.assertIn("contract_address=", request.full_url)


class TronApplicationHistoryTests(SimpleTestCase):
    ADDRESS = "TUoHaVjx7n5xz8LwPRDckgFrDWhMhuSuJM"

    @patch.object(history_service, "TronReadOnlyClient")
    @patch.object(history_service, "settings")
    def test_tron_wallet_is_routed_and_converted(
        self,
        mock_settings: Mock,
        mock_client_class: Mock,
    ) -> None:
        mock_settings.TRON_RPC_URL = "https://api.example.invalid"
        mock_settings.TRON_API_KEY = "test-key"
        mock_settings.TRON_RPC_TIMEOUT = 10
        mock_settings.TRON_TRANSACTION_HISTORY_LIMIT = 25
        mock_settings.TRON_USDT_CONTRACT_ADDRESS = ""
        mock_client_class.return_value.get_transaction_history.return_value = (
            TronTransactionHistory(
                transactions=(
                    TronTransaction(
                        transaction_hash="c" * 64,
                        transaction_type="transfer",
                        status="confirmed",
                        amount=Decimal("2.25"),
                        block_number=100,
                        timestamp=1_700_000_000,
                    ),
                ),
                available=True,
            )
        )
        wallet = SimpleNamespace(
            address=self.ADDRESS,
            network=SimpleNamespace(slug="tron-mainnet"),
        )

        result = get_wallet_transaction_history(wallet=wallet)

        self.assertTrue(result.available)
        self.assertEqual(result.transactions[0].amount, Decimal("2.25"))
        self.assertEqual(result.transactions[0].network, "TRON Mainnet")
        self.assertEqual(result.transactions[0].symbol, "TRX")
        mock_client_class.return_value.get_transaction_history.assert_called_once_with(
            self.ADDRESS,
            limit=25,
        )

        kwargs = mock_client_class.call_args.kwargs
        self.assertEqual(
            set(kwargs),
            {"rpc_url", "api_key", "timeout"},
        )

    @patch.object(history_service, "TronReadOnlyClient")
    @patch.object(history_service, "settings")
    def test_provider_failure_is_unavailable(
        self,
        mock_settings: Mock,
        mock_client_class: Mock,
    ) -> None:
        mock_settings.TRON_RPC_URL = "https://api.example.invalid"
        mock_settings.TRON_API_KEY = ""
        mock_settings.TRON_RPC_TIMEOUT = 10
        mock_settings.TRON_TRANSACTION_HISTORY_LIMIT = 25
        mock_settings.TRON_USDT_CONTRACT_ADDRESS = ""
        mock_client_class.return_value.get_transaction_history.side_effect = (
            tron.TronTemporaryError("unavailable")
        )
        wallet = SimpleNamespace(
            address=self.ADDRESS,
            network=SimpleNamespace(slug="tron-mainnet"),
        )

        result = get_wallet_transaction_history(wallet=wallet)

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())
