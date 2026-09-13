"""
Tests for HappyWallet Token Scanner DEX discovery.

These tests verify the read-only Ethereum DEX discovery layer.

Security expectations
---------------------
- No private keys.
- No signing.
- No transaction submission.
- No token approvals.
- No swaps.
- No automatic trading.
"""

from __future__ import annotations

from unittest.mock import PropertyMock, patch

from django.test import SimpleTestCase

from web3 import Web3

from ..services.dexy import (
    DEFAULT_MAX_BLOCKS,
    DexDiscoveryConfigurationError,
    DexDiscoveryRPCError,
    DexFactory,
    DexPool,
    EthereumDexDiscovery,
    PAIR_CREATED_EVENT_TOPIC,
)


class DexFactoryTests(SimpleTestCase):
    """Tests for DexFactory."""

    def test_factory_normalizes_address(self):
        address = "0x" + "11" * 20

        factory = DexFactory(
            name="Test DEX",
            address=address,
        )

        self.assertEqual(
            factory.address,
            Web3.to_checksum_address(address),
        )

    def test_factory_rejects_empty_name(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            DexFactory(
                name="",
                address="0x" + "11" * 20,
            )

    def test_factory_rejects_whitespace_name(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            DexFactory(
                name="   ",
                address="0x" + "11" * 20,
            )

    def test_factory_rejects_empty_address(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            DexFactory(
                name="Test DEX",
                address="",
            )

    def test_factory_rejects_invalid_address(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            DexFactory(
                name="Test DEX",
                address="not-an-address",
            )

    def test_factory_uses_pair_created_topic_by_default(self):
        factory = DexFactory(
            name="Test DEX",
            address="0x" + "11" * 20,
        )

        self.assertEqual(
            factory.pair_created_topic,
            PAIR_CREATED_EVENT_TOPIC,
        )

    def test_factory_accepts_custom_pair_created_topic(self):
        custom_topic = "0x" + "aa" * 32

        factory = DexFactory(
            name="Test DEX",
            address="0x" + "11" * 20,
            pair_created_topic=custom_topic,
        )

        self.assertEqual(
            factory.pair_created_topic,
            custom_topic,
        )

    def test_factory_rejects_empty_custom_topic(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            DexFactory(
                name="Test DEX",
                address="0x" + "11" * 20,
                pair_created_topic="",
            )


class DexPoolTests(SimpleTestCase):
    """Tests for DexPool."""

    def test_tokens_property(self):
        pool = DexPool(
            dex_name="Test DEX",
            factory_address="0x" + "11" * 20,
            pool_address="0x" + "22" * 20,
            token0="0x" + "33" * 20,
            token1="0x" + "44" * 20,
            block_number=100,
            transaction_hash="0x" + "55" * 32,
        )

        self.assertEqual(
            pool.tokens,
            (
                pool.token0,
                pool.token1,
            ),
        )


class EthereumDexDiscoveryConfigurationTests(
    SimpleTestCase,
):
    """Tests for EthereumDexDiscovery configuration."""

    def test_empty_rpc_url_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery("")

    def test_whitespace_rpc_url_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery("   ")

    def test_timeout_must_be_positive(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                timeout=0,
            )

    def test_boolean_timeout_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                timeout=True,
            )

    def test_log_chunk_size_must_be_positive(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                log_chunk_size=0,
            )

    def test_boolean_log_chunk_size_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                log_chunk_size=True,
            )

    def test_max_blocks_must_be_positive(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                max_blocks=0,
            )

    def test_boolean_max_blocks_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                max_blocks=True,
            )

    def test_max_pools_must_be_positive(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                max_pools=0,
            )

    def test_boolean_max_pools_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            EthereumDexDiscovery(
                "http://localhost:8545",
                max_pools=True,
            )


class EthereumDexDiscoveryValidationTests(
    SimpleTestCase,
):
    """Tests for block and range validation."""

    def setUp(self):
        self.discovery = EthereumDexDiscovery(
            "http://localhost:8545",
        )

    def test_negative_block_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_block_number(
                -1,
                field_name="from_block",
            )

    def test_boolean_block_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_block_number(
                True,
                field_name="from_block",
            )

    def test_non_integer_block_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_block_number(
                "not-a-block",
                field_name="from_block",
            )

    def test_integer_string_block_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_block_number(
                "100",
                field_name="from_block",
            )

    def test_float_block_is_rejected(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_block_number(
                100.0,
                field_name="from_block",
            )

    def test_range_must_be_ordered(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_range(
                from_block=200,
                to_block=100,
            )

    def test_range_cannot_exceed_limit(self):
        with self.assertRaises(DexDiscoveryConfigurationError):
            self.discovery._validate_range(
                from_block=1,
                to_block=DEFAULT_MAX_BLOCKS + 1,
            )

    def test_valid_range_is_accepted(self):
        self.discovery._validate_range(
            from_block=100,
            to_block=109,
        )


class EthereumDexDiscoveryNormalizationTests(
    SimpleTestCase,
):
    """Tests for safe external-data normalization."""

    def test_valid_address_is_normalized(self):
        address = (
            "0x1111111111111111111111111111111111111111"
        )

        result = EthereumDexDiscovery._normalize_address(
            address,
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(address),
        )

    def test_invalid_address_returns_none(self):
        result = EthereumDexDiscovery._normalize_address(
            "not-an-address",
        )

        self.assertIsNone(result)

    def test_bytes_address_returns_none(self):
        result = EthereumDexDiscovery._normalize_address(
            b"\x11" * 20,
        )

        self.assertIsNone(result)

    def test_invalid_bytes_address_returns_none(self):
        result = EthereumDexDiscovery._normalize_address(
            b"bad",
        )

        self.assertIsNone(result)

    def test_missing_address_returns_none(self):
        result = EthereumDexDiscovery._normalize_address(
            None,
        )

        self.assertIsNone(result)

    def test_block_number_is_extracted(self):
        result = (
            EthereumDexDiscovery._extract_block_number(
                "123",
            )
        )

        self.assertEqual(
            result,
            123,
        )

    def test_missing_block_number_returns_none(self):
        result = (
            EthereumDexDiscovery._extract_block_number(
                None,
            )
        )

        self.assertIsNone(result)

    def test_invalid_block_number_returns_none(self):
        result = (
            EthereumDexDiscovery._extract_block_number(
                "not-a-number",
            )
        )

        self.assertIsNone(result)

    def test_negative_block_number_returns_none(self):
        result = (
            EthereumDexDiscovery._extract_block_number(
                -1,
            )
        )

        self.assertIsNone(result)

    def test_boolean_block_number_returns_none(self):
        result = (
            EthereumDexDiscovery._extract_block_number(
                True,
            )
        )

        self.assertIsNone(result)

    def test_integer_block_number_is_preserved(self):
        result = (
            EthereumDexDiscovery._extract_block_number(
                123,
            )
        )

        self.assertEqual(
            result,
            123,
        )


class EthereumDexDiscoveryDecodingTests(
    SimpleTestCase,
):
    """Tests for PairCreated event decoding."""

    def test_indexed_address_is_decoded(self):
        address = (
            "0x1111111111111111111111111111111111111111"
        )

        topic = (
            "0x"
            + "00" * 12
            + "11" * 20
        )

        result = (
            EthereumDexDiscovery._decode_indexed_address(
                topic,
            )
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(address),
        )

    def test_indexed_bytes_address_is_decoded(self):
        address = (
            "0x1111111111111111111111111111111111111111"
        )

        topic = bytes.fromhex(
            "00" * 12 + "11" * 20,
        )

        result = (
            EthereumDexDiscovery._decode_indexed_address(
                topic,
            )
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(address),
        )

    def test_invalid_indexed_topic_returns_none(self):
        result = (
            EthereumDexDiscovery._decode_indexed_address(
                "0x1234",
            )
        )

        self.assertIsNone(result)

    def test_missing_indexed_topic_returns_none(self):
        result = (
            EthereumDexDiscovery._decode_indexed_address(
                None,
            )
        )

        self.assertIsNone(result)

    def test_pool_address_is_decoded_from_data(self):
        pool = (
            "0x2222222222222222222222222222222222222222"
        )

        encoded_address = (
            "00" * 12
            + "22" * 20
        )

        encoded_count = (
            "00" * 31
            + "01"
        )

        data = (
            "0x"
            + encoded_address
            + encoded_count
        )

        result = (
            EthereumDexDiscovery._decode_pool_address(
                data,
            )
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(pool),
        )

    def test_invalid_pool_data_returns_none(self):
        result = (
            EthereumDexDiscovery._decode_pool_address(
                "0x1234",
            )
        )

        self.assertIsNone(result)

    def test_missing_pool_data_returns_none(self):
        result = (
            EthereumDexDiscovery._decode_pool_address(
                None,
            )
        )

        self.assertIsNone(result)

    def test_pool_data_without_second_word_is_still_decodable(self):
        pool = (
            "0x2222222222222222222222222222222222222222"
        )

        data = (
            "0x"
            + "00" * 12
            + "22" * 20
        )

        result = (
            EthereumDexDiscovery._decode_pool_address(
                data,
            )
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(pool),
        )


class EthereumDexDiscoveryLogParsingTests(
    SimpleTestCase,
):
    """Tests for PairCreated log parsing."""

    def setUp(self):
        self.factory = DexFactory(
            name="Test DEX",
            address="0x" + "11" * 20,
        )

        self.discovery = EthereumDexDiscovery(
            "http://localhost:8545",
            factories=[self.factory],
        )

    @staticmethod
    def _topic_for_address(address: str) -> str:
        return (
            "0x"
            + "00" * 12
            + address.removeprefix("0x")
        )

    @staticmethod
    def _pair_created_log(
        *,
        factory_address: str,
        token0: str = "0x" + "33" * 20,
        token1: str = "0x" + "44" * 20,
        pool: str = "0x" + "22" * 20,
        block_number: int = 123,
        transaction_hash: str = "0x" + "55" * 32,
        event_topic: str = PAIR_CREATED_EVENT_TOPIC,
    ):
        data = (
            "0x"
            + "00" * 12
            + pool.removeprefix("0x")
            + "00" * 31
            + "01"
        )

        return {
            "address": factory_address,
            "topics": [
                event_topic,
                EthereumDexDiscoveryLogParsingTests
                ._topic_for_address(token0),
                EthereumDexDiscoveryLogParsingTests
                ._topic_for_address(token1),
            ],
            "data": data,
            "blockNumber": block_number,
            "transactionHash": transaction_hash,
        }

    def test_valid_pair_created_log_is_parsed(self):
        token0 = "0x" + "33" * 20
        token1 = "0x" + "44" * 20
        pool = "0x" + "22" * 20

        log = self._pair_created_log(
            factory_address=self.factory.address,
            token0=token0,
            token1=token1,
            pool=pool,
        )

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNotNone(result)

        assert result is not None

        self.assertEqual(
            result.dex_name,
            "Test DEX",
        )

        self.assertEqual(
            result.factory_address,
            self.factory.address,
        )

        self.assertEqual(
            result.pool_address,
            Web3.to_checksum_address(pool),
        )

        self.assertEqual(
            result.token0,
            Web3.to_checksum_address(token0),
        )

        self.assertEqual(
            result.token1,
            Web3.to_checksum_address(token1),
        )

        self.assertEqual(
            result.block_number,
            123,
        )

        self.assertEqual(
            result.transaction_hash,
            "0x" + "55" * 32,
        )

    def test_log_from_different_factory_is_rejected(self):
        other_factory = DexFactory(
            name="Other DEX",
            address="0x" + "66" * 20,
        )

        log = self._pair_created_log(
            factory_address=other_factory.address,
        )

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_missing_topics_are_rejected(self):
        log = {
            "address": self.factory.address,
            "topics": [],
            "data": "0x",
            "blockNumber": 123,
            "transactionHash": "0x" + "55" * 32,
        }

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_too_few_topics_are_rejected(self):
        log = {
            "address": self.factory.address,
            "topics": [
                PAIR_CREATED_EVENT_TOPIC,
            ],
            "data": "0x" + "00" * 64,
            "blockNumber": 123,
            "transactionHash": "0x" + "55" * 32,
        }

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_wrong_event_topic_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
            event_topic="0x" + "aa" * 32,
        )

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_missing_block_number_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
        )
        del log["blockNumber"]

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_invalid_block_number_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
        )
        log["blockNumber"] = "not-a-block"

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_missing_transaction_hash_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
        )
        del log["transactionHash"]

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_invalid_token0_topic_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
        )
        log["topics"][1] = "0x1234"

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_invalid_token1_topic_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
        )
        log["topics"][2] = "0x1234"

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)

    def test_invalid_pool_data_is_rejected(self):
        log = self._pair_created_log(
            factory_address=self.factory.address,
        )
        log["data"] = "0x1234"

        result = self.discovery._pool_from_log(
            factory=self.factory,
            log=log,
        )

        self.assertIsNone(result)


class EthereumDexDiscoveryRPCMockTests(
    SimpleTestCase,
):
    """Tests for RPC-facing behavior."""

    def setUp(self):
        self.factory = DexFactory(
            name="Test DEX",
            address="0x" + "11" * 20,
        )

        self.discovery = EthereumDexDiscovery(
            "http://localhost:8545",
            factories=[self.factory],
            max_blocks=10,
        )

    @patch.object(
        EthereumDexDiscovery,
        "_ensure_connection",
    )
    def test_latest_block(
        self,
        ensure_connection,
    ):
        with patch(
            "web3.eth.Eth.block_number",
            new_callable=PropertyMock,
            return_value=123,
        ):
            result = self.discovery.latest_block()

        self.assertEqual(
            result,
            123,
        )

        ensure_connection.assert_called_once()

    def test_discover_without_factories_returns_warning(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
        )

        result = discovery.discover(
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.pool_count,
            0,
        )

        self.assertEqual(
            result.logs_examined,
            0,
        )

        self.assertEqual(
            result.factories_examined,
            0,
        )

        self.assertTrue(
            result.complete,
        )

        self.assertTrue(
            result.warnings,
        )

    @patch.object(
        EthereumDexDiscovery,
        "_ensure_connection",
    )
    @patch.object(
        EthereumDexDiscovery,
        "_get_factory_logs",
    )
    def test_discover_counts_logs(
        self,
        get_factory_logs,
        ensure_connection,
    ):
        get_factory_logs.return_value = []

        result = self.discovery.discover(
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.logs_examined,
            0,
        )

        self.assertEqual(
            result.factories_examined,
            1,
        )

        ensure_connection.assert_called_once()
        get_factory_logs.assert_called_once_with(
            factory=self.factory,
            from_block=100,
            to_block=109,
        )

    @patch.object(
        EthereumDexDiscovery,
        "_ensure_connection",
    )
    @patch.object(
        EthereumDexDiscovery,
        "_get_factory_logs",
    )
    def test_rpc_failure_becomes_warning(
        self,
        get_factory_logs,
        ensure_connection,
    ):
        get_factory_logs.side_effect = (
            DexDiscoveryRPCError(
                "RPC failure",
            )
        )

        result = self.discovery.discover(
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.pool_count,
            0,
        )

        self.assertFalse(
            result.complete,
        )

        self.assertTrue(
            result.warnings,
        )

        self.assertIn(
            "RPC failure",
            result.warnings[0],
        )

        ensure_connection.assert_called_once()

    @patch.object(
        EthereumDexDiscovery,
        "_ensure_connection",
    )
    @patch.object(
        EthereumDexDiscovery,
        "_get_factory_logs",
    )
    def test_discover_parses_factory_logs(
        self,
        get_factory_logs,
        ensure_connection,
    ):
        token0 = "0x" + "33" * 20
        token1 = "0x" + "44" * 20
        pool = "0x" + "22" * 20

        data = (
            "0x"
            + "00" * 12
            + "22" * 20
            + "00" * 31
            + "01"
        )

        log = {
            "address": self.factory.address,
            "topics": [
                PAIR_CREATED_EVENT_TOPIC,
                (
                    "0x"
                    + "00" * 12
                    + token0.removeprefix("0x")
                ),
                (
                    "0x"
                    + "00" * 12
                    + token1.removeprefix("0x")
                ),
            ],
            "data": data,
            "blockNumber": 123,
            "transactionHash": "0x" + "55" * 32,
        }

        get_factory_logs.return_value = [log]

        result = self.discovery.discover(
            from_block=120,
            to_block=129,
        )

        self.assertEqual(
            result.pool_count,
            1,
        )

        self.assertEqual(
            result.pools_discovered,
            1,
        )

        self.assertEqual(
            result.logs_examined,
            1,
        )

        self.assertEqual(
            result.factories_examined,
            1,
        )

        self.assertTrue(
            result.complete,
        )

        discovered_pool = result.pools[0]

        self.assertEqual(
            discovered_pool.pool_address,
            Web3.to_checksum_address(pool),
        )

        self.assertEqual(
            discovered_pool.token0,
            Web3.to_checksum_address(token0),
        )

        self.assertEqual(
            discovered_pool.token1,
            Web3.to_checksum_address(token1),
        )

        ensure_connection.assert_called_once()


class EthereumDexDiscoveryResultTests(
    SimpleTestCase,
):
    """Tests for discovery result behavior."""

    def test_empty_result_has_zero_pool_count(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
        )

        result = discovery.discover(
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.pool_count,
            0,
        )

    def test_block_count_is_inclusive(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
        )

        result = discovery.discover(
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.block_count,
            10,
        )

    def test_single_block_range_has_one_block(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
        )

        result = discovery.discover(
            from_block=100,
            to_block=100,
        )

        self.assertEqual(
            result.block_count,
            1,
        )

    def test_discovery_range_is_recorded(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
        )

        result = discovery.discover(
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.from_block,
            100,
        )

        self.assertEqual(
            result.to_block,
            109,
        )

class EthereumDexDiscoverySafetyTests(
    SimpleTestCase,
):
    """Tests for read-only and bounded behavior."""

    def test_range_is_bounded_before_rpc_connection(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
            factories=[],
            max_blocks=10,
        )

        with patch.object(
            discovery,
            "_ensure_connection",
        ) as ensure_connection:
            with self.assertRaises(
                DexDiscoveryConfigurationError,
            ):
                discovery.discover(
                    from_block=100,
                    to_block=200,
                )

        ensure_connection.assert_not_called()

    def test_reversed_range_is_rejected_before_rpc_connection(self):
        discovery = EthereumDexDiscovery(
            "http://localhost:8545",
            factories=[],
        )

        with patch.object(
            discovery,
            "_ensure_connection",
        ) as ensure_connection:
            with self.assertRaises(
                DexDiscoveryConfigurationError,
            ):
                discovery.discover(
                    from_block=200,
                    to_block=100,
                )

        ensure_connection.assert_not_called()

    @patch.object(
        EthereumDexDiscovery,
        "_ensure_connection",
    )
    @patch.object(
        EthereumDexDiscovery,
        "_get_factory_logs",
    )
    def test_discovery_does_not_submit_transactions(
        self,
        get_factory_logs,
        ensure_connection,
    ):
        """
        Verify that DEX discovery is strictly read-only.

        Web3.py normally exposes transaction-related APIs through
        web3.eth. Their existence is expected and does not mean the
        discovery service is capable of trading.

        The actual security boundary is behavioral.

        Discovery must never call:

        - send_raw_transaction()
        - send_transaction()
        - sign_transaction()

        If any of these methods are called, the test fails immediately.
        """

        get_factory_logs.return_value = []

        discovery = EthereumDexDiscovery(
            "https://example.invalid",
            factories=(
                DexFactory(
                    name="Test DEX",
                    address=(
                        "0x1111111111111111111111111111111111111111"
                    ),
                ),
            ),
        )

        with patch.object(
            discovery.web3.eth,
            "send_raw_transaction",
            side_effect=AssertionError(
                "DEX discovery attempted transaction submission "
                "through send_raw_transaction()."
            ),
        ) as send_raw_transaction, patch.object(
            discovery.web3.eth,
            "send_transaction",
            side_effect=AssertionError(
                "DEX discovery attempted transaction submission "
                "through send_transaction()."
            ),
        ) as send_transaction, patch.object(
            discovery.web3.eth,
            "sign_transaction",
            side_effect=AssertionError(
                "DEX discovery attempted transaction signing "
                "through sign_transaction()."
            ),
        ) as sign_transaction:
            result = discovery.discover(
                from_block=100,
                to_block=109,
            )

        ensure_connection.assert_called_once()

        get_factory_logs.assert_called_once_with(
            factory=discovery.factories[0],
            from_block=100,
            to_block=109,
        )

        self.assertEqual(
            result.pools,
            (),
        )

        self.assertEqual(
            result.pools_discovered,
            0,
        )

        self.assertEqual(
            result.logs_examined,
            0,
        )

        self.assertTrue(
            result.complete,
        )

        send_raw_transaction.assert_not_called()
        send_transaction.assert_not_called()
        sign_transaction.assert_not_called()

    @staticmethod
    def _factory():
        return DexFactory(
            name="Test DEX",
            address="0x" + "11" * 20,
        )
        
        