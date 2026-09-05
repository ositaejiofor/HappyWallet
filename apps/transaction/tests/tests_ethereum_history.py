"""
Unit tests for the Ethereum transaction-history adapter.

These tests never contact a real Ethereum RPC provider.

Provider communication is mocked at the private ``_rpc_call`` boundary so
that the adapter can be tested deterministically, quickly, and without
network access.

Coverage includes:

    Block-scanning history
    ----------------------
    - public address validation
    - RPC URL validation
    - block-limit normalization
    - transaction filtering
    - sender/recipient matching
    - case-insensitive address matching
    - transaction normalization
    - ETH amount conversion
    - transfer classification
    - contract classification
    - empty history
    - RPC failures
    - invalid provider responses
    - invalid transaction data
    - multiple transactions
    - immutable result DTOs

    Alchemy indexed history
    -----------------------
    - native ETH transfer normalization
    - sender queries
    - recipient queries
    - empty indexed history
    - pagination
    - duplicate transaction removal
    - token transfer normalization
    - expected Alchemy categories
    - historical block range
    - newest-first ordering
    - provider failures
    - validation
    - immutable result DTOs
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.transaction.services.networks.ethereum import (
    ETHEREUM_NETWORK_NAME,
    ETHEREUM_SYMBOL,
    MAX_BLOCK_LIMIT,
    EthereumHistoryError,
    EthereumTransaction,
    EthereumTransactionHistory,
    get_indexed_transaction_history,
    get_transaction_history,
)


class EthereumTransactionHistoryTests(SimpleTestCase):
    """Tests for the bounded Ethereum block-scanning history adapter."""

    RPC_URL = "https://example.invalid/ethereum"

    ADDRESS = "0x1111111111111111111111111111111111111111"
    OTHER_ADDRESS = "0x2222222222222222222222222222222222222222"
    THIRD_ADDRESS = "0x3333333333333333333333333333333333333333"

    TX_HASH_A = (
        "0x"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    TX_HASH_B = (
        "0x"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    TX_HASH_C = (
        "0x"
        "cccccccccccccccccccccccccccccccc"
        "cccccccccccccccccccccccccccccccc"
    )

    TIMESTAMP = int("65a00000", 16)

    # ======================================================================
    # FIXTURES
    # ======================================================================

    def _rpc_side_effect(
        self,
        *,
        block_number: str = "0x64",
        transactions: list[dict] | None = None,
    ):
        """
        Build a deterministic fake JSON-RPC response function.

        The helper mirrors the block-scanning methods used by the adapter:

            eth_blockNumber
            eth_getBlockByNumber
        """

        if transactions is None:
            transactions = [
                self._transfer_transaction(),
            ]

        def side_effect(
            *,
            rpc_url,
            method,
            params,
            timeout,
        ):
            if method == "eth_blockNumber":
                return block_number

            if method == "eth_getBlockByNumber":
                requested_block = int(params[0], 16)

                return {
                    "number": hex(requested_block),
                    "timestamp": "0x65a00000",
                    "transactions": transactions,
                }

            raise AssertionError(
                f"Unexpected RPC method: {method}"
            )

        return side_effect

    def _transfer_transaction(
        self,
        *,
        sender: str | None = None,
        recipient: str | None = None,
        transaction_hash: str | None = None,
        value: str = "0xde0b6b3a7640000",
        input_data: str = "0x",
    ) -> dict:
        """Create a deterministic Ethereum transaction fixture."""

        return {
            "hash": transaction_hash or self.TX_HASH_A,
            "from": sender or self.ADDRESS,
            "to": recipient or self.OTHER_ADDRESS,
            "value": value,
            "input": input_data,
        }

    # ======================================================================
    # BASIC SUCCESS PATH
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_returns_transactions_involving_wallet(
        self,
        mock_rpc,
    ):
        """Transactions involving the wallet are normalized."""

        mock_rpc.side_effect = self._rpc_side_effect()

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertIsInstance(
            result,
            EthereumTransactionHistory,
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 1)

        transaction = result.transactions[0]

        self.assertIsInstance(
            transaction,
            EthereumTransaction,
        )

        self.assertEqual(
            transaction.transaction_hash,
            self.TX_HASH_A,
        )

        self.assertEqual(
            transaction.transaction_type,
            "transfer",
        )

        self.assertEqual(
            transaction.status,
            "confirmed",
        )

        self.assertEqual(
            transaction.network,
            ETHEREUM_NETWORK_NAME,
        )

        self.assertEqual(
            transaction.symbol,
            ETHEREUM_SYMBOL,
        )

        self.assertEqual(
            transaction.amount,
            Decimal("1"),
        )

        self.assertEqual(
            transaction.block_number,
            100,
        )

        self.assertEqual(
            transaction.timestamp,
            self.TIMESTAMP,
        )

    # ======================================================================
    # ADDRESS MATCHING
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_matches_wallet_as_sender(
        self,
        mock_rpc,
    ):
        """A transaction is returned when the wallet is the sender."""

        transaction = self._transfer_transaction(
            sender=self.ADDRESS,
            recipient=self.OTHER_ADDRESS,
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertEqual(len(result.transactions), 1)

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_matches_wallet_as_recipient(
        self,
        mock_rpc,
    ):
        """A transaction is returned when the wallet is the recipient."""

        transaction = self._transfer_transaction(
            sender=self.OTHER_ADDRESS,
            recipient=self.ADDRESS,
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertEqual(len(result.transactions), 1)

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_address_matching_is_case_insensitive(
        self,
        mock_rpc,
    ):
        """Ethereum address matching ignores checksum casing."""

        transaction = self._transfer_transaction(
            sender=self.ADDRESS.upper(),
            recipient=self.OTHER_ADDRESS,
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertEqual(len(result.transactions), 1)

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_transaction_not_involving_wallet_is_ignored(
        self,
        mock_rpc,
    ):
        """Transactions unrelated to the wallet are ignored."""

        transaction = self._transfer_transaction(
            sender=self.OTHER_ADDRESS,
            recipient=self.THIRD_ADDRESS,
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

    # ======================================================================
    # EMPTY HISTORY
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_returns_empty_history_when_block_has_no_transactions(
        self,
        mock_rpc,
    ):
        """An empty block produces available but empty history."""

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_returns_empty_history_when_no_transaction_matches(
        self,
        mock_rpc,
    ):
        """A successful scan with no matching transactions is available."""

        transaction = self._transfer_transaction(
            transaction_hash=self.TX_HASH_B,
            sender=self.OTHER_ADDRESS,
            recipient=self.THIRD_ADDRESS,
            value="0x0",
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

    # ======================================================================
    # TRANSACTION CLASSIFICATION
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_contract_transaction_is_classified_correctly(
        self,
        mock_rpc,
    ):
        """Non-empty input data is classified as a contract transaction."""

        transaction = self._transfer_transaction(
            transaction_hash=self.TX_HASH_C,
            sender=self.OTHER_ADDRESS,
            recipient=self.ADDRESS,
            value="0x0",
            input_data="0xa9059cbb",
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 1)

        self.assertEqual(
            result.transactions[0].transaction_type,
            "contract",
        )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_empty_input_is_classified_as_transfer(
        self,
        mock_rpc,
    ):
        """Empty input data is classified as a native transfer."""

        transaction = self._transfer_transaction(
            input_data="",
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertEqual(
            result.transactions[0].transaction_type,
            "transfer",
        )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_zero_value_transaction_is_supported(
        self,
        mock_rpc,
    ):
        """A zero-value transaction remains a valid transaction."""

        transaction = self._transfer_transaction(
            value="0x0",
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertEqual(len(result.transactions), 1)
        self.assertEqual(
            result.transactions[0].amount,
            Decimal("0"),
        )

    # ======================================================================
    # VALIDATION
    # ======================================================================

    def test_rejects_invalid_address(self):
        """Invalid Ethereum addresses are rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address="invalid",
            )

    def test_rejects_empty_address(self):
        """An empty Ethereum address is rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address="",
            )

    def test_rejects_address_with_invalid_length(self):
        """Ethereum addresses must contain exactly 40 hex digits."""

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address="0x1234",
            )

    def test_rejects_address_with_invalid_hexadecimal_data(self):
        """Non-hexadecimal Ethereum addresses are rejected."""

        invalid_address = (
            "0x"
            "gggggggggggggggggggggggggggggggggggggggg"
        )

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address=invalid_address,
            )

    def test_rejects_empty_rpc_url(self):
        """An empty RPC endpoint is rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url="",
                address=self.ADDRESS,
            )

    def test_rejects_non_http_rpc_url(self):
        """Only HTTP(S) RPC endpoints are accepted."""

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url="ftp://example.com/rpc",
                address=self.ADDRESS,
            )

    def test_rejects_invalid_block_limit(self):
        """A non-positive block limit is rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.ADDRESS,
                block_limit=0,
            )

    # ======================================================================
    # BLOCK LIMIT
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_block_limit_is_bounded(
        self,
        mock_rpc,
    ):
        """The adapter never scans more than MAX_BLOCK_LIMIT blocks."""

        calls = []

        def side_effect(
            *,
            rpc_url,
            method,
            params,
            timeout,
        ):
            calls.append((method, params))

            if method == "eth_blockNumber":
                return "0x1000"

            return {
                "timestamp": "0x65a00000",
                "transactions": [],
            }

        mock_rpc.side_effect = side_effect

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1000,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

        block_calls = [
            call
            for call in calls
            if call[0] == "eth_getBlockByNumber"
        ]

        self.assertEqual(
            len(block_calls),
            MAX_BLOCK_LIMIT,
        )

    # ======================================================================
    # RPC FAILURES
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_rpc_failure_is_exposed_as_history_error(
        self,
        mock_rpc,
    ):
        """RPC failures are represented by EthereumHistoryError."""

        mock_rpc.side_effect = EthereumHistoryError(
            "provider unavailable"
        )

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.ADDRESS,
                block_limit=1,
            )

    # ======================================================================
    # INVALID PROVIDER RESPONSES
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_invalid_latest_block_is_rejected(
        self,
        mock_rpc,
    ):
        """An invalid latest block number raises a history error."""

        mock_rpc.return_value = "not-a-number"

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.ADDRESS,
                block_limit=1,
            )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_invalid_block_response_is_rejected(
        self,
        mock_rpc,
    ):
        """A non-object block response raises a history error."""

        def side_effect(
            *,
            rpc_url,
            method,
            params,
            timeout,
        ):
            if method == "eth_blockNumber":
                return "0x64"

            return []

        mock_rpc.side_effect = side_effect

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.ADDRESS,
                block_limit=1,
            )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_invalid_transaction_list_is_rejected(
        self,
        mock_rpc,
    ):
        """A malformed transaction collection raises a history error."""

        def side_effect(
            *,
            rpc_url,
            method,
            params,
            timeout,
        ):
            if method == "eth_blockNumber":
                return "0x64"

            return {
                "timestamp": "0x65a00000",
                "transactions": "invalid",
            }

        mock_rpc.side_effect = side_effect

        with self.assertRaises(EthereumHistoryError):
            get_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.ADDRESS,
                block_limit=1,
            )

    # ======================================================================
    # INVALID TRANSACTION DATA
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_invalid_transaction_hash_is_ignored(
        self,
        mock_rpc,
    ):
        """Malformed transaction hashes are safely ignored."""

        transaction = self._transfer_transaction(
            transaction_hash="0x1234",
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_transaction_without_hash_is_ignored(
        self,
        mock_rpc,
    ):
        """Transactions without a hash are safely ignored."""

        transaction = self._transfer_transaction()
        transaction.pop("hash")

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[transaction],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_non_dictionary_transaction_is_ignored(
        self,
        mock_rpc,
    ):
        """Malformed transaction entries do not crash the scan."""

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[
                "invalid transaction",
                self._transfer_transaction(),
            ],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 1)

    # ======================================================================
    # MULTIPLE TRANSACTIONS
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_multiple_matching_transactions_are_returned(
        self,
        mock_rpc,
    ):
        """All matching transactions in the scanned block are returned."""

        first = self._transfer_transaction(
            transaction_hash=self.TX_HASH_A,
        )

        second = self._transfer_transaction(
            transaction_hash=self.TX_HASH_B,
            sender=self.OTHER_ADDRESS,
            recipient=self.ADDRESS,
        )

        mock_rpc.side_effect = self._rpc_side_effect(
            transactions=[
                first,
                second,
            ],
        )

        result = get_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 2)

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_A,
        )

        self.assertEqual(
            result.transactions[1].transaction_hash,
            self.TX_HASH_B,
        )

    # ======================================================================
    # DTO IMMUTABILITY
    # ======================================================================

    def test_transaction_history_is_immutable(self):
        """EthereumTransactionHistory DTOs are immutable."""

        result = EthereumTransactionHistory(
            transactions=(),
            available=True,
        )

        with self.assertRaises(AttributeError):
            result.available = False

    def test_ethereum_transaction_is_immutable(self):
        """EthereumTransaction DTOs are immutable."""

        transaction = EthereumTransaction(
            transaction_hash=self.TX_HASH_A,
            transaction_type="transfer",
            status="confirmed",
        )

        with self.assertRaises(AttributeError):
            transaction.status = "failed"


class AlchemyIndexedTransactionHistoryTests(SimpleTestCase):
    """
    Tests for the Alchemy indexed transaction-history implementation.

    These tests intentionally mock ``_rpc_call()``.

    No real Alchemy API request is made.
    """

    RPC_URL = (
        "https://eth-mainnet.g.alchemy.com/v2/test-api-key"
    )

    WALLET_ADDRESS = (
        "0xF7452E4501543ee7E7a5BA1210Ddc0E48dfFBc81"
    )

    OTHER_ADDRESS = (
        "0x1111111111111111111111111111111111111111"
    )

    TOKEN_ADDRESS = (
        "0x2222222222222222222222222222222222222222"
    )

    TX_HASH_1 = (
        "0x"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    TX_HASH_2 = (
        "0x"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    # ======================================================================
    # ALCHEMY FIXTURES
    # ======================================================================

    def _alchemy_transfer(
        self,
        *,
        transaction_hash: str = TX_HASH_1,
        from_address: str = OTHER_ADDRESS,
        to_address: str = WALLET_ADDRESS,
        value: str = "1.5",
        asset: str = "ETH",
        block_num: str = "0x100",
        timestamp: str = "2026-09-03T12:00:00Z",
        category: str = "external",
        raw_address: str | None = None,
        decimals: int = 18,
        raw_value: str = "0x14d1120d7b160000",
    ) -> dict:
        """Create a deterministic Alchemy Asset Transfers item."""

        return {
            "blockNum": block_num,
            "uniqueId": f"{transaction_hash}:0",
            "hash": transaction_hash,
            "from": from_address,
            "to": to_address,
            "value": value,
            "asset": asset,
            "category": category,
            "rawContract": {
                "address": raw_address,
                "decimals": decimals,
                "value": raw_value,
            },
            "metadata": {
                "blockTimestamp": timestamp,
            },
        }

    def _alchemy_response(
        self,
        transfers,
        *,
        page_key: str | None = None,
    ) -> dict:
        """Build a deterministic Alchemy RPC result."""

        response = {
            "transfers": list(transfers),
        }

        if page_key is not None:
            response["pageKey"] = page_key

        return response

    # ======================================================================
    # BASIC INDEXED HISTORY
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_returns_native_transfer(
        self,
        mock_rpc,
    ):
        """A native ETH transfer is converted into the public DTO."""

        transfer = self._alchemy_transfer()

        mock_rpc.return_value = self._alchemy_response(
            [transfer],
        )

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertIsInstance(
            result,
            EthereumTransactionHistory,
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 1)

        transaction = result.transactions[0]

        self.assertIsInstance(
            transaction,
            EthereumTransaction,
        )

        self.assertEqual(
            transaction.transaction_hash,
            self.TX_HASH_1,
        )

        self.assertEqual(
            transaction.network,
            ETHEREUM_NETWORK_NAME,
        )

        self.assertEqual(
            transaction.symbol,
            ETHEREUM_SYMBOL,
        )

        self.assertEqual(
            transaction.amount,
            Decimal("1.5"),
        )

        self.assertEqual(
            transaction.block_number,
            256,
        )

        self.assertEqual(
            transaction.timestamp,
            1788436800,
        )

        self.assertEqual(
            transaction.status,
            "confirmed",
        )

    # ======================================================================
    # SENDER QUERY
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_queries_wallet_as_sender(
        self,
        mock_rpc,
    ):
        """The adapter queries Alchemy for outgoing transfers."""

        transfer = self._alchemy_transfer(
            from_address=self.WALLET_ADDRESS,
            to_address=self.OTHER_ADDRESS,
            value="2",
        )

        mock_rpc.return_value = self._alchemy_response(
            [transfer],
        )

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertEqual(
            len(result.transactions),
            1,
        )

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_1,
        )

        first_call = mock_rpc.call_args_list[0]

        params = first_call.kwargs["params"]

        self.assertEqual(
            params[0]["fromAddress"],
            self.WALLET_ADDRESS,
        )

        self.assertNotIn(
            "toAddress",
            params[0],
        )

    # ======================================================================
    # RECIPIENT QUERY
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_queries_wallet_as_recipient(
        self,
        mock_rpc,
    ):
        """The adapter queries Alchemy for incoming transfers."""

        transfer = self._alchemy_transfer(
            from_address=self.OTHER_ADDRESS,
            to_address=self.WALLET_ADDRESS,
            value="3",
        )

        # First query: outgoing side.
        # Second query: incoming side.
        mock_rpc.side_effect = [
            self._alchemy_response([]),
            self._alchemy_response([transfer]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertEqual(
            len(result.transactions),
            1,
        )

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_1,
        )

        self.assertEqual(
            mock_rpc.call_count,
            2,
        )

        second_call = mock_rpc.call_args_list[1]

        params = second_call.kwargs["params"]

        self.assertEqual(
            params[0]["toAddress"],
            self.WALLET_ADDRESS,
        )

        self.assertNotIn(
            "fromAddress",
            params[0],
        )

    # ======================================================================
    # EMPTY HISTORY
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_handles_empty_history(
        self,
        mock_rpc,
    ):
        """No indexed transfers produce available empty history."""

        mock_rpc.return_value = {
            "transfers": [],
        }

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

        # Both sender and recipient queries should be made.
        self.assertEqual(
            mock_rpc.call_count,
            2,
        )

    # ======================================================================
    # PAGINATION
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_follows_page_key(
        self,
        mock_rpc,
    ):
        """Alchemy pagination is followed until pageKey disappears."""

        first_transfer = self._alchemy_transfer(
            transaction_hash=self.TX_HASH_1,
            value="1",
            block_num="0x100",
        )

        second_transfer = self._alchemy_transfer(
            transaction_hash=self.TX_HASH_2,
            value="2",
            block_num="0x101",
        )

        # The implementation queries sender and recipient.
        # The first query returns two pages.
        # The second query returns nothing.
        mock_rpc.side_effect = [
            self._alchemy_response(
                [first_transfer],
                page_key="NEXT_PAGE",
            ),
            self._alchemy_response(
                [second_transfer],
            ),
            self._alchemy_response([]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertEqual(
            len(result.transactions),
            2,
        )

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_2,
        )

        self.assertEqual(
            result.transactions[1].transaction_hash,
            self.TX_HASH_1,
        )

        self.assertEqual(
            mock_rpc.call_count,
            3,
        )

        second_call_params = (
            mock_rpc.call_args_list[1]
            .kwargs["params"]
        )

        self.assertEqual(
            second_call_params[0]["pageKey"],
            "NEXT_PAGE",
        )

    # ======================================================================
    # DUPLICATE HASHES
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_deduplicates_transaction_hashes(
        self,
        mock_rpc,
    ):
        """
        A transaction returned by both sender and recipient queries is
        represented only once.
        """

        transfer = self._alchemy_transfer(
            transaction_hash=self.TX_HASH_1,
        )

        mock_rpc.side_effect = [
            self._alchemy_response([transfer]),
            self._alchemy_response([transfer]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertEqual(
            len(result.transactions),
            1,
        )

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_1,
        )

    # ======================================================================
    # TOKEN NORMALIZATION
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_normalizes_token_transfer(
        self,
        mock_rpc,
    ):
        """
        Token metadata returned by Alchemy is normalized into the public
        transaction DTO.
        """

        transfer = self._alchemy_transfer(
            value="100",
            asset="USDC",
            category="erc20",
            raw_address=self.TOKEN_ADDRESS,
            decimals=6,
            raw_value="0x5f5e100",
        )

        mock_rpc.side_effect = [
            self._alchemy_response([transfer]),
            self._alchemy_response([]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertEqual(
            len(result.transactions),
            1,
        )

        transaction = result.transactions[0]

        self.assertEqual(
            transaction.transaction_hash,
            self.TX_HASH_1,
        )

        self.assertEqual(
            transaction.symbol,
            "USDC",
        )

    # ======================================================================
    # ALCHEMY REQUEST CONFIGURATION
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_requests_expected_categories(
        self,
        mock_rpc,
    ):
        """The indexed adapter requests native ETH categories."""

        mock_rpc.return_value = {
            "transfers": [],
        }

        get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertTrue(mock_rpc.called)

        params = mock_rpc.call_args.kwargs["params"]

        categories = params[0]["category"]

        self.assertIn(
            "external",
            categories,
        )

        self.assertIn(
            "internal",
            categories,
        )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_uses_full_historical_range(
        self,
        mock_rpc,
    ):
        """Alchemy is queried from genesis through the latest block."""

        mock_rpc.return_value = {
            "transfers": [],
        }

        get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        params = mock_rpc.call_args.kwargs["params"]

        self.assertEqual(
            params[0]["fromBlock"],
            "0x0",
        )

        self.assertEqual(
            params[0]["toBlock"],
            "latest",
        )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_requests_non_zero_transfers(
        self,
        mock_rpc,
    ):
        """Zero-value filtering remains explicitly disabled."""

        mock_rpc.return_value = {
            "transfers": [],
        }

        get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        params = mock_rpc.call_args.kwargs["params"]

        self.assertFalse(
            params[0]["excludeZeroValue"],
        )

    # ======================================================================
    # RESULT ORDERING
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_orders_newest_first(
        self,
        mock_rpc,
    ):
        """Indexed results are returned newest-first."""

        older = self._alchemy_transfer(
            transaction_hash=self.TX_HASH_1,
            block_num="0x100",
            timestamp="2026-09-03T10:00:00Z",
        )

        newer = self._alchemy_transfer(
            transaction_hash=self.TX_HASH_2,
            block_num="0x200",
            timestamp="2026-09-03T12:00:00Z",
        )

        mock_rpc.side_effect = [
            self._alchemy_response(
                [older, newer],
            ),
            self._alchemy_response([]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertEqual(
            len(result.transactions),
            2,
        )

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_2,
        )

        self.assertEqual(
            result.transactions[1].transaction_hash,
            self.TX_HASH_1,
        )

    # ======================================================================
    # PROVIDER FAILURES
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_propagates_provider_failure(
        self,
        mock_rpc,
    ):
        """Provider failures are exposed as EthereumHistoryError."""

        mock_rpc.side_effect = EthereumHistoryError(
            "Ethereum RPC returned an error."
        )

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.WALLET_ADDRESS,
            )

    # ======================================================================
    # VALIDATION
    # ======================================================================

    def test_indexed_history_rejects_invalid_address(self):
        """Invalid Ethereum addresses are rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url=self.RPC_URL,
                address="not-an-ethereum-address",
            )

    def test_indexed_history_rejects_empty_address(self):
        """Empty Ethereum addresses are rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url=self.RPC_URL,
                address="",
            )

    def test_indexed_history_rejects_invalid_rpc_url(self):
        """Invalid RPC URLs are rejected."""

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url="not-a-url",
                address=self.WALLET_ADDRESS,
            )

    def test_indexed_history_rejects_non_alchemy_rpc_url(self):
        """The indexed method requires an Alchemy Ethereum endpoint."""

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url="https://example.com/ethereum",
                address=self.WALLET_ADDRESS,
            )

    # ======================================================================
    # IMMUTABILITY
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_result_is_immutable(
        self,
        mock_rpc,
    ):
        """Indexed transaction DTOs cannot be modified."""

        transfer = self._alchemy_transfer()

        mock_rpc.side_effect = [
            self._alchemy_response([transfer]),
            self._alchemy_response([]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        transaction = result.transactions[0]

        with self.assertRaises(AttributeError):
            transaction.transaction_hash = "changed"

    # ======================================================================
    # INVALID INDEXED PROVIDER RESPONSES
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_rejects_invalid_provider_result(
        self,
        mock_rpc,
    ):
        """Malformed Alchemy results are rejected."""

        mock_rpc.return_value = []

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.WALLET_ADDRESS,
            )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_rejects_invalid_transfers_collection(
        self,
        mock_rpc,
    ):
        """The transfers collection must be a list."""

        mock_rpc.return_value = {
            "transfers": "invalid",
        }

        with self.assertRaises(EthereumHistoryError):
            get_indexed_transaction_history(
                rpc_url=self.RPC_URL,
                address=self.WALLET_ADDRESS,
            )

    # ======================================================================
    # INVALID INDEXED TRANSFERS
    # ======================================================================

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_ignores_invalid_transfer_entries(
        self,
        mock_rpc,
    ):
        """Malformed individual transfer entries are ignored safely."""

        valid_transfer = self._alchemy_transfer()

        mock_rpc.side_effect = [
            self._alchemy_response(
                [
                    "invalid transfer",
                    valid_transfer,
                ],
            ),
            self._alchemy_response([]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertTrue(result.available)
        self.assertEqual(
            len(result.transactions),
            1,
        )

        self.assertEqual(
            result.transactions[0].transaction_hash,
            self.TX_HASH_1,
        )

    @patch(
        "apps.transaction.services.networks.ethereum._rpc_call"
    )
    def test_indexed_history_ignores_invalid_transaction_hash(
        self,
        mock_rpc,
    ):
        """Transfers with malformed transaction hashes are ignored."""

        invalid_transfer = self._alchemy_transfer(
            transaction_hash="0x1234",
        )

        mock_rpc.side_effect = [
            self._alchemy_response([invalid_transfer]),
            self._alchemy_response([]),
        ]

        result = get_indexed_transaction_history(
            rpc_url=self.RPC_URL,
            address=self.WALLET_ADDRESS,
        )

        self.assertTrue(result.available)
        self.assertEqual(
            result.transactions,
            (),
        )
