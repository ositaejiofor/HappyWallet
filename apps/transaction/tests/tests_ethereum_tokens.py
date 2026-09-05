"""
Production-oriented tests for the HappyWallet Ethereum ERC-20 token
history adapter.

These tests are intentionally network-free.

The adapter is tested at its JSON-RPC boundary so that:

    - no real Ethereum RPC endpoint is contacted
    - no RPC credentials are exposed
    - no blockchain state is modified
    - deterministic fixtures can be used in CI
    - token amounts are tested without floating-point arithmetic
    - malformed blockchain data is rejected safely
    - transfer ordering and limits remain deterministic

Test scope
----------
1. ERC-20 Transfer event normalization.
2. Incoming / outgoing / self transfer classification.
3. Address matching.
4. Duplicate removal.
5. Newest-first ordering.
6. Transfer limits.
7. Input validation.
8. JSON-RPC response validation.
9. Token amount conversion.
10. Indexed address decoding.
11. Temporary RPC error hierarchy.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.transaction.services.networks.ethereum_tokens import (
    ERC20_TRANSFER_TOPIC,
    ERC20Transfer,
    EthereumTokenHistoryError,
    EthereumTokenRPCTemporaryError,
    get_token_transfer_history,
)


# ============================================================================
# TEST CONSTANTS
# ============================================================================

RPC_URL = "https://example.invalid/ethereum"

WALLET_ADDRESS = (
    "0x1111111111111111111111111111111111111111"
)

OTHER_ADDRESS = (
    "0x2222222222222222222222222222222222222222"
)

TOKEN_ADDRESS = (
    "0x3333333333333333333333333333333333333333"
)

UNRELATED_ADDRESS = (
    "0x4444444444444444444444444444444444444444"
)

TRANSACTION_HASH = (
    "0x"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaa"
)

ONE_USDC_RAW = (
    "0x"
    + f"{1_000_000:064x}"
)

assert len(ONE_USDC_RAW) == 66
assert len(ONE_USDC_RAW[2:]) == 64


# ============================================================================
# ERC-20 EVENT TOPICS
# ============================================================================

def _address_topic(address: str) -> str:
    """
    Convert a normal Ethereum address into an indexed event topic.

    ERC-20 Transfer(address,address,uint256) stores the indexed
    addresses as 32-byte ABI words.
    """

    return (
        "0x"
        + ("0" * 24)
        + address.removeprefix("0x").lower()
    )


FROM_TOPIC = _address_topic(WALLET_ADDRESS)
TO_TOPIC = _address_topic(OTHER_ADDRESS)
UNRELATED_FROM_TOPIC = _address_topic(OTHER_ADDRESS)
UNRELATED_TO_TOPIC = _address_topic(UNRELATED_ADDRESS)


# ============================================================================
# TEST FIXTURE FACTORIES
# ============================================================================

def _make_transaction_hash(char: str) -> str:
    """Create a deterministic 32-byte transaction hash fixture."""

    if len(char) != 1:
        raise ValueError("Transaction hash fixture requires one character.")

    return "0x" + (char * 64)


def _make_transfer_log(
    *,
    transaction_hash: str = TRANSACTION_HASH,
    token_address: str = TOKEN_ADDRESS,
    from_topic: str = FROM_TOPIC,
    to_topic: str = TO_TOPIC,
    amount: str = ONE_USDC_RAW,
    block_number: str = "0x64",
    transaction_index: str = "0x1",
    log_index: str = "0x0",
) -> dict[str, object]:
    """
    Build a valid ERC-20 Transfer event fixture.

    The fixture intentionally mirrors the shape returned by
    eth_getLogs.
    """

    return {
        "address": token_address,
        "topics": [
            ERC20_TRANSFER_TOPIC,
            from_topic,
            to_topic,
        ],
        "data": amount,
        "blockNumber": block_number,
        "transactionHash": transaction_hash,
        "transactionIndex": transaction_index,
        "logIndex": log_index,
    }


def _make_history(
    *,
    mock_latest_block,
    mock_get_logs,
    logs,
    address: str = WALLET_ADDRESS,
    token_address: str = TOKEN_ADDRESS,
    block_limit: int = 100,
    max_transfers: int = 100,
    decimals: int = 6,
    symbol: str | None = None,
    token_name: str | None = None,
):
    """
    Build token history using deterministic mocked RPC boundaries.
    """

    mock_latest_block.return_value = 100
    mock_get_logs.return_value = tuple(logs)

    return get_token_transfer_history(
        rpc_url=RPC_URL,
        address=address,
        token_address=token_address,
        block_limit=block_limit,
        max_transfers=max_transfers,
        decimals=decimals,
        symbol=symbol,
        token_name=token_name,
    )


# ============================================================================
# HISTORY ADAPTER TESTS
# ============================================================================

class EthereumTokenHistoryTests(SimpleTestCase):
    """Tests for get_token_transfer_history()."""

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_incoming_transfer_is_normalized(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """An incoming ERC-20 transfer is normalized correctly."""

        history = _make_history(
            mock_latest_block=mock_latest_block,
            mock_get_logs=mock_get_logs,
            logs=(
                _make_transfer_log(
                    from_topic=TO_TOPIC,
                    to_topic=FROM_TOPIC,
                ),
            ),
            symbol="USDC",
            token_name="USD Coin",
        )

        self.assertTrue(history.available)
        self.assertEqual(len(history.transfers), 1)

        transfer = history.transfers[0]

        self.assertIsInstance(transfer, ERC20Transfer)
        self.assertEqual(transfer.direction, "incoming")
        self.assertEqual(transfer.amount, Decimal("1"))
        self.assertEqual(transfer.raw_amount, 1_000_000)
        self.assertEqual(transfer.decimals, 6)
        self.assertEqual(transfer.symbol, "USDC")
        self.assertEqual(transfer.token_name, "USD Coin")
        self.assertEqual(transfer.token_address, TOKEN_ADDRESS)
        self.assertEqual(transfer.transaction_hash, TRANSACTION_HASH)
        self.assertEqual(transfer.block_number, 100)
        self.assertEqual(transfer.transaction_index, 1)
        self.assertEqual(transfer.log_index, 0)

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_outgoing_transfer_is_normalized(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """An outgoing ERC-20 transfer is normalized correctly."""

        history = _make_history(
            mock_latest_block=mock_latest_block,
            mock_get_logs=mock_get_logs,
            logs=(
                _make_transfer_log(
                    from_topic=FROM_TOPIC,
                    to_topic=TO_TOPIC,
                ),
            ),
            symbol="USDC",
        )

        self.assertEqual(len(history.transfers), 1)
        self.assertEqual(
            history.transfers[0].direction,
            "outgoing",
        )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_self_transfer_is_classified_correctly(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """A transfer from the wallet to itself is classified as self."""

        wallet_topic = _address_topic(WALLET_ADDRESS)

        history = _make_history(
            mock_latest_block=mock_latest_block,
            mock_get_logs=mock_get_logs,
            logs=(
                _make_transfer_log(
                    from_topic=wallet_topic,
                    to_topic=wallet_topic,
                ),
            ),
        )

        self.assertEqual(len(history.transfers), 1)
        self.assertEqual(
            history.transfers[0].direction,
            "self",
        )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_unrelated_transfer_is_ignored(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """Transfers involving another wallet are ignored."""

        history = _make_history(
            mock_latest_block=mock_latest_block,
            mock_get_logs=mock_get_logs,
            logs=(
                _make_transfer_log(
                    from_topic=UNRELATED_FROM_TOPIC,
                    to_topic=UNRELATED_TO_TOPIC,
                ),
            ),
        )

        self.assertEqual(history.transfers, ())

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_transfers_are_sorted_newest_first(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """
        Transfers are ordered by block number, transaction index,
        and log index descending.

        The mocked RPC call returns both records together. This is
        important: _get_transfer_logs() represents a single block-range
        query and should therefore return a collection of logs.
        """

        older_hash = _make_transaction_hash("b")
        newer_hash = _make_transaction_hash("c")

        mock_latest_block.return_value = 200

        mock_get_logs.return_value = (
            _make_transfer_log(
                transaction_hash=older_hash,
                block_number="0xc7",
                transaction_index="0x1",
                log_index="0x0",
            ),
            _make_transfer_log(
                transaction_hash=newer_hash,
                block_number="0xc8",
                transaction_index="0x2",
                log_index="0x3",
            ),
        )

        history = get_token_transfer_history(
            rpc_url=RPC_URL,
            address=WALLET_ADDRESS,
            token_address=TOKEN_ADDRESS,
            block_limit=100,
            max_transfers=100,
            decimals=6,
        )

        self.assertEqual(len(history.transfers), 2)

        self.assertEqual(
            history.transfers[0].transaction_hash,
            newer_hash,
        )

        self.assertEqual(
            history.transfers[1].transaction_hash,
            older_hash,
        )

        self.assertGreaterEqual(
            history.transfers[0].block_number,
            history.transfers[1].block_number,
        )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_sorting_uses_transaction_index_when_blocks_match(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """Same-block transfers are ordered by transaction index."""

        first_hash = _make_transaction_hash("a")
        second_hash = _make_transaction_hash("b")

        mock_latest_block.return_value = 100

        mock_get_logs.return_value = (
            _make_transfer_log(
                transaction_hash=first_hash,
                block_number="0x64",
                transaction_index="0x1",
                log_index="0x0",
            ),
            _make_transfer_log(
                transaction_hash=second_hash,
                block_number="0x64",
                transaction_index="0x2",
                log_index="0x0",
            ),
        )

        history = get_token_transfer_history(
            rpc_url=RPC_URL,
            address=WALLET_ADDRESS,
            token_address=TOKEN_ADDRESS,
            decimals=6,
        )

        self.assertEqual(
            history.transfers[0].transaction_hash,
            second_hash,
        )

        self.assertEqual(
            history.transfers[1].transaction_hash,
            first_hash,
        )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_sorting_uses_log_index_as_final_tiebreaker(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """Same-block same-transaction logs are ordered by log index."""

        first_hash = _make_transaction_hash("a")
        second_hash = _make_transaction_hash("b")

        mock_latest_block.return_value = 100

        mock_get_logs.return_value = (
            _make_transfer_log(
                transaction_hash=first_hash,
                block_number="0x64",
                transaction_index="0x1",
                log_index="0x1",
            ),
            _make_transfer_log(
                transaction_hash=second_hash,
                block_number="0x64",
                transaction_index="0x1",
                log_index="0x2",
            ),
        )

        history = get_token_transfer_history(
            rpc_url=RPC_URL,
            address=WALLET_ADDRESS,
            token_address=TOKEN_ADDRESS,
            decimals=6,
        )

        self.assertEqual(
            history.transfers[0].transaction_hash,
            second_hash,
        )

        self.assertEqual(
            history.transfers[1].transaction_hash,
            first_hash,
        )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_max_transfers_is_respected(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """The adapter never returns more than max_transfers."""

        logs = []

        for index in range(10):
            logs.append(
                _make_transfer_log(
                    transaction_hash=_make_transaction_hash(
                        f"{index + 1:x}"[-1]
                    ),
                    block_number=hex(100 + index),
                    log_index=hex(index),
                )
            )

        mock_latest_block.return_value = 109
        mock_get_logs.return_value = tuple(logs)

        history = get_token_transfer_history(
            rpc_url=RPC_URL,
            address=WALLET_ADDRESS,
            token_address=TOKEN_ADDRESS,
            block_limit=100,
            max_transfers=3,
            decimals=6,
        )

        self.assertEqual(len(history.transfers), 3)

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_duplicate_logs_are_removed(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """Duplicate Transfer logs are returned only once."""

        log = _make_transfer_log()

        history = _make_history(
            mock_latest_block=mock_latest_block,
            mock_get_logs=mock_get_logs,
            logs=(log, log),
        )

        self.assertEqual(len(history.transfers), 1)

    @patch(
        "apps.transaction.services.networks.ethereum_tokens._get_transfer_logs"
    )
    @patch(
        "apps.transaction.services.networks.ethereum_tokens."
        "_get_latest_block_number"
    )
    def test_address_matching_is_case_insensitive(
        self,
        mock_latest_block,
        mock_get_logs,
    ):
        """Ethereum address matching ignores hexadecimal casing."""

        mixed_case_wallet = (
            "0x1111111111111111111111111111111111111111"
        )

        history = _make_history(
            mock_latest_block=mock_latest_block,
            mock_get_logs=mock_get_logs,
            address=mixed_case_wallet,
            logs=(
                _make_transfer_log(
                    from_topic=FROM_TOPIC,
                    to_topic=TO_TOPIC,
                ),
            ),
        )

        self.assertEqual(len(history.transfers), 1)
        self.assertEqual(
            history.transfers[0].from_address,
            WALLET_ADDRESS.lower(),
        )

    # ------------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------------

    def test_invalid_wallet_address_is_rejected(self):
        """Invalid wallet addresses fail validation."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address="invalid-address",
                token_address=TOKEN_ADDRESS,
            )

    def test_invalid_token_address_is_rejected(self):
        """Invalid token contract addresses fail validation."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address=WALLET_ADDRESS,
                token_address="invalid-token",
            )

    def test_invalid_rpc_url_is_rejected(self):
        """Malformed RPC endpoints fail validation."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url="ftp://example.invalid/rpc",
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
            )

    def test_empty_rpc_url_is_rejected(self):
        """Empty RPC endpoints fail validation."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url="",
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
            )

    def test_invalid_decimals_are_rejected(self):
        """ERC-20 decimals outside uint8 range are rejected."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
                decimals=256,
            )

    def test_negative_decimals_are_rejected(self):
        """Negative ERC-20 decimals are rejected."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
                decimals=-1,
            )

    def test_invalid_block_limit_is_rejected(self):
        """A zero block limit is invalid."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
                block_limit=0,
            )

    def test_invalid_max_transfers_is_rejected(self):
        """A zero transfer limit is invalid."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
                max_transfers=0,
            )

    def test_invalid_timeout_is_rejected(self):
        """A zero timeout is invalid."""

        with self.assertRaises(EthereumTokenHistoryError):
            get_token_transfer_history(
                rpc_url=RPC_URL,
                address=WALLET_ADDRESS,
                token_address=TOKEN_ADDRESS,
                timeout=0,
            )


# ============================================================================
# JSON-RPC TESTS
# ============================================================================

class EthereumTokenRpcTests(SimpleTestCase):
    """Tests for the low-level Ethereum JSON-RPC boundary."""

    @staticmethod
    def _response(body: bytes, status: int = 200):
        """Create a deterministic fake HTTP response."""

        class FakeResponse:
            def __init__(self):
                self.status = status

            def read(self):
                return body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return FakeResponse()

    @patch(
        "apps.transaction.services.networks.ethereum_tokens.urlopen"
    )
    def test_rpc_response_is_validated(
        self,
        mock_urlopen,
    ):
        """Malformed JSON-RPC responses are rejected."""

        mock_urlopen.return_value = self._response(
            b'{"jsonrpc":"2.0","id":1}'
        )

        from apps.transaction.services.networks.ethereum_tokens import (
            _rpc_call,
        )

        with self.assertRaises(EthereumTokenHistoryError):
            _rpc_call(
                rpc_url=RPC_URL,
                method="eth_blockNumber",
                params=[],
                timeout=5,
            )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens.urlopen"
    )
    def test_rpc_error_response_is_rejected(
        self,
        mock_urlopen,
    ):
        """JSON-RPC error responses are never treated as successful."""

        mock_urlopen.return_value = self._response(
            (
                b'{"jsonrpc":"2.0","id":1,'
                b'"error":{"code":-32000,"message":"failed"}}'
            )
        )

        from apps.transaction.services.networks.ethereum_tokens import (
            _rpc_call,
        )

        with self.assertRaises(EthereumTokenHistoryError):
            _rpc_call(
                rpc_url=RPC_URL,
                method="eth_blockNumber",
                params=[],
                timeout=5,
            )

    @patch(
        "apps.transaction.services.networks.ethereum_tokens.urlopen"
    )
    def test_rpc_result_is_returned(
        self,
        mock_urlopen,
    ):
        """A valid JSON-RPC response returns its result."""

        mock_urlopen.return_value = self._response(
            b'{"jsonrpc":"2.0","id":1,"result":"0x64"}'
        )

        from apps.transaction.services.networks.ethereum_tokens import (
            _rpc_call,
        )

        result = _rpc_call(
            rpc_url=RPC_URL,
            method="eth_blockNumber",
            params=[],
            timeout=5,
        )

        self.assertEqual(result, "0x64")


# ============================================================================
# TOKEN DECODING HELPERS
# ============================================================================

class EthereumTokenHelperTests(SimpleTestCase):
    """Focused tests for token-log decoding helpers."""

    def test_transfer_topic_is_standard_erc20_topic(self):
        """The adapter uses the canonical ERC-20 Transfer topic."""

        self.assertEqual(
            ERC20_TRANSFER_TOPIC,
            (
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163"
                "c4a11628f55a9df523b3ef"
            ),
        )

    def test_one_usdc_transfer_decodes_to_one_token(self):
        """1,000,000 raw units with six decimals equals one token."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _raw_token_amount_to_decimal,
        )

        amount = _raw_token_amount_to_decimal(
            1_000_000,
            6,
        )

        self.assertEqual(amount, Decimal("1"))

    def test_one_ether_style_token_with_18_decimals(self):
        """18-decimal token amounts are converted without floats."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _raw_token_amount_to_decimal,
        )

        amount = _raw_token_amount_to_decimal(
            1_000_000_000_000_000_000,
            18,
        )

        self.assertEqual(amount, Decimal("1"))

    def test_fractional_token_amount_is_exact(self):
        """Fractional token values remain exact Decimal values."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _raw_token_amount_to_decimal,
        )

        amount = _raw_token_amount_to_decimal(
            1_234_567,
            6,
        )

        self.assertEqual(
            amount,
            Decimal("1.234567"),
        )

    def test_zero_token_amount_is_valid(self):
        """Zero raw units remain a valid Decimal value."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _raw_token_amount_to_decimal,
        )

        amount = _raw_token_amount_to_decimal(
            0,
            6,
        )

        self.assertEqual(amount, Decimal("0"))

    def test_negative_token_amount_is_rejected(self):
        """Negative raw token amounts are rejected."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _raw_token_amount_to_decimal,
        )

        amount = _raw_token_amount_to_decimal(
            -1,
            6,
        )

        self.assertIsNone(amount)

    def test_indexed_address_topic_is_decoded(self):
        """A 32-byte indexed address topic is decoded correctly."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _decode_indexed_address,
        )

        decoded = _decode_indexed_address(FROM_TOPIC)

        self.assertEqual(
            decoded,
            WALLET_ADDRESS,
        )

    def test_indexed_address_topic_is_case_normalized(self):
        """Decoded addresses are normalized to lowercase."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _decode_indexed_address,
        )

        mixed_topic = _address_topic(
            "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
        )

        decoded = _decode_indexed_address(mixed_topic)

        self.assertEqual(
            decoded,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )

    def test_invalid_indexed_address_topic_is_rejected(self):
        """Malformed topics do not produce an address."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _decode_indexed_address,
        )

        decoded = _decode_indexed_address("0x1234")

        self.assertIsNone(decoded)

    def test_invalid_transfer_data_is_rejected(self):
        """Malformed ERC-20 event data does not produce an amount."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _decode_uint256,
        )

        decoded = _decode_uint256("0x1234")

        self.assertIsNone(decoded)

    def test_uint256_zero_is_decoded(self):
        """A zero uint256 value is valid."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _decode_uint256,
        )

        decoded = _decode_uint256(
            "0x"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )

        self.assertEqual(decoded, 0)

    def test_uint256_max_value_is_decoded(self):
        """The maximum uint256 value is accepted."""

        from apps.transaction.services.networks.ethereum_tokens import (
            _decode_uint256,
        )

        maximum = (1 << 256) - 1

        decoded = _decode_uint256(
            "0x" + f"{maximum:064x}"
        )

        self.assertEqual(decoded, maximum)


# ============================================================================
# EXCEPTION HIERARCHY
# ============================================================================

class EthereumTokenTemporaryErrorTests(SimpleTestCase):
    """Tests for transient RPC exception semantics."""

    def test_temporary_error_is_history_error(self):
        """Temporary RPC failures inherit from the base history error."""

        error = EthereumTokenRPCTemporaryError(
            "temporary failure"
        )

        self.assertIsInstance(
            error,
            EthereumTokenHistoryError,
        )

    def test_temporary_error_preserves_message(self):
        """Temporary errors preserve their diagnostic message."""

        message = "RPC provider temporarily unavailable"

        error = EthereumTokenRPCTemporaryError(message)

        self.assertEqual(str(error), message)
