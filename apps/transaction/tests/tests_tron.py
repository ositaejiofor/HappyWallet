"""Mocked tests for HappyWallet's read-only TRON adapter."""

from __future__ import annotations

import json
from decimal import Decimal
from io import BytesIO
from unittest.mock import patch
from urllib.error import URLError

from django.test import SimpleTestCase, override_settings

from apps.transaction.services.broadcaster import BroadcastRejectedError
from apps.transaction.services.networks.tron import (
    TronBroadcaster,
    TronNetworkError,
    TronReadOnlyClient,
    TronResponseError,
    TronTemporaryError,
)


VALID_ADDRESS = "T" + ("A" * 33)


class FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self.status = status
        self._stream = BytesIO(json.dumps(payload).encode("utf-8"))

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


@override_settings(
    TRON_RPC_URL="https://api.trongrid.io",
    TRON_API_KEY="test-key-never-real",
    TRON_RPC_TIMEOUT=7,
    RPC_MAX_RETRIES=0,
    RPC_RETRY_BACKOFF_SECONDS=0,
)
class TronReadOnlyClientTests(SimpleTestCase):
    @patch("apps.transaction.services.networks.tron.urlopen")
    def test_latest_block_sends_api_key_and_timeout(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeResponse(
            {
                "blockID": "abc123",
                "block_header": {"raw_data": {"number": 123}},
            }
        )

        result = TronReadOnlyClient().get_now_block()

        self.assertEqual(result["blockID"], "abc123")
        request = mocked_urlopen.call_args.args[0]
        headers = {
            key.lower(): value
            for key, value in request.header_items()
        }
        self.assertEqual(headers["tron-pro-api-key"], "test-key-never-real")
        self.assertEqual(mocked_urlopen.call_args.kwargs["timeout"], 7)
        self.assertEqual(request.full_url, "https://api.trongrid.io/wallet/getnowblock")

    @patch("apps.transaction.services.networks.tron.urlopen")
    def test_account_query_uses_visible_base58_address(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeResponse(
            {"address": VALID_ADDRESS, "balance": 1_250_000}
        )

        client = TronReadOnlyClient()
        account = client.get_account(VALID_ADDRESS)

        self.assertEqual(account["balance"], 1_250_000)
        request = mocked_urlopen.call_args.args[0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["address"], VALID_ADDRESS)
        self.assertIs(body["visible"], True)

    @patch("apps.transaction.services.networks.tron.urlopen")
    def test_trx_balance_converts_sun_to_trx(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeResponse({"balance": 1_250_000})

        balance = TronReadOnlyClient().get_trx_balance(VALID_ADDRESS)

        self.assertEqual(balance, Decimal("1.25"))

    def test_invalid_address_is_rejected_before_network_access(self):
        with patch("apps.transaction.services.networks.tron.urlopen") as mocked:
            with self.assertRaises(TronNetworkError):
                TronReadOnlyClient().get_account("not-a-tron-address")
        mocked.assert_not_called()

    @patch("apps.transaction.services.networks.tron.urlopen")
    def test_invalid_latest_block_fails_closed(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeResponse({"unexpected": True})

        with self.assertRaises(TronResponseError):
            TronReadOnlyClient().get_now_block()

    @patch("apps.transaction.services.networks.tron.time.sleep")
    @patch("apps.transaction.services.networks.tron.urlopen")
    def test_temporary_failure_is_bounded(self, mocked_urlopen, mocked_sleep):
        mocked_urlopen.side_effect = URLError("offline")
        client = TronReadOnlyClient(max_retries=2, retry_backoff_seconds=0)

        with self.assertRaises(TronTemporaryError):
            client.get_now_block()

        self.assertEqual(mocked_urlopen.call_count, 3)
        self.assertEqual(mocked_sleep.call_count, 0)

    def test_tron_broadcasting_is_always_rejected(self):
        with self.assertRaises(BroadcastRejectedError):
            TronBroadcaster.broadcast(raw_transaction=b"signed-but-disabled")
