from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase
from web3 import Web3
from web3.exceptions import Web3Exception

from apps.token_scanner.services.liquidity import (
    DEAD_ADDRESSES,
    LiquidityAnalysis,
    LiquidityPool,
    LiquidityRPCError,
    EVMLiquidityAnalyzer,
    InvalidLiquidityAddressError,
)


RPC_URL = "http://example-rpc.invalid"

TOKEN_ADDRESS = "0x1111111111111111111111111111111111111111"
POOL_ADDRESS = "0x2222222222222222222222222222222222222222"
PAIRED_TOKEN_ADDRESS = "0x3333333333333333333333333333333333333333"


class EVMLiquidityAnalyzerTests(SimpleTestCase):
    """Tests for the read-only EVM liquidity analyzer."""

    def setUp(self):
        self.analyzer = EVMLiquidityAnalyzer(
            RPC_URL,
        )

    # ========================================================================
    # Initialization
    # ========================================================================

    def test_analyzer_initializes(self):
        self.assertEqual(
            self.analyzer.rpc_url,
            RPC_URL,
        )

        self.assertIsNotNone(
            self.analyzer.web3,
        )

    def test_empty_rpc_url_is_rejected(self):
        with self.assertRaises(ValueError):
            EVMLiquidityAnalyzer("")

    def test_whitespace_rpc_url_is_rejected(self):
        with self.assertRaises(ValueError):
            EVMLiquidityAnalyzer("   ")

    # ========================================================================
    # Address validation
    # ========================================================================

    def test_invalid_address_is_rejected(self):
        with self.assertRaises(
            InvalidLiquidityAddressError,
        ):
            self.analyzer._validate_address(
                "not-an-address",
            )

    def test_empty_address_is_rejected(self):
        with self.assertRaises(
            InvalidLiquidityAddressError,
        ):
            self.analyzer._validate_address("")

    def test_non_string_address_is_rejected(self):
        with self.assertRaises(
            InvalidLiquidityAddressError,
        ):
            self.analyzer._validate_address(None)

    def test_valid_address_is_checksummed(self):
        result = self.analyzer._validate_address(
            TOKEN_ADDRESS,
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(
                TOKEN_ADDRESS,
            ),
        )

    # ========================================================================
    # Numeric helpers
    # ========================================================================

    def test_normalize_reserve_converts_raw_value(self):
        result = self.analyzer._normalize_reserve(
            1_500_000_000,
            6,
        )

        self.assertEqual(
            result,
            Decimal("1500"),
        )

    def test_normalize_reserve_supports_zero(self):
        result = self.analyzer._normalize_reserve(
            0,
            18,
        )

        self.assertEqual(
            result,
            Decimal("0"),
        )

    def test_normalize_reserve_rejects_negative_value(self):
        with self.assertRaises(ValueError):
            self.analyzer._normalize_reserve(
                -1,
                18,
            )

    def test_normalize_reserve_rejects_negative_decimals(self):
        with self.assertRaises(ValueError):
            self.analyzer._normalize_reserve(
                100,
                -1,
            )

    # ========================================================================
    # Result objects
    # ========================================================================

    def test_thin_liquidity_is_true_below_threshold(self):
        result = LiquidityAnalysis(
            token_address=TOKEN_ADDRESS,
            total_liquidity_usd=Decimal("10000"),
        )

        self.assertTrue(
            result.is_thin_liquidity,
        )

    def test_thin_liquidity_is_false_at_threshold(self):
        result = LiquidityAnalysis(
            token_address=TOKEN_ADDRESS,
            total_liquidity_usd=Decimal("25000"),
        )

        self.assertFalse(
            result.is_thin_liquidity,
        )

    def test_thin_liquidity_is_false_without_usd_value(self):
        result = LiquidityAnalysis(
            token_address=TOKEN_ADDRESS,
            total_liquidity_usd=None,
        )

        self.assertFalse(
            result.is_thin_liquidity,
        )

    def test_liquidity_pool_defaults_are_safe(self):
        pool = LiquidityPool(
            pool_address=POOL_ADDRESS,
            token_address=TOKEN_ADDRESS,
        )

        self.assertEqual(
            pool.paired_token,
            "",
        )

        self.assertEqual(
            pool.dex_name,
            "",
        )

        self.assertIsNone(
            pool.reserve_token,
        )

        self.assertIsNone(
            pool.reserve_paired,
        )

        self.assertIsNone(
            pool.liquidity_usd,
        )

        self.assertTrue(
            pool.is_active,
        )

        self.assertFalse(
            pool.is_burn_address,
        )

    # ========================================================================
    # Analyze - no pools
    # ========================================================================

    def test_analyze_without_pools_returns_empty_analysis(self):
        result = self.analyzer.analyze(
            TOKEN_ADDRESS,
        )

        self.assertEqual(
            result.token_address,
            Web3.to_checksum_address(
                TOKEN_ADDRESS,
            ),
        )

        self.assertEqual(
            result.pools,
            (),
        )

        self.assertEqual(
            result.liquidity_pool_count,
            0,
        )

        self.assertFalse(
            result.has_liquidity,
        )

        self.assertIsNone(
            result.total_liquidity_usd,
        )

        self.assertIsNone(
            result.deepest_pool_address,
        )

        self.assertIn(
            "No known liquidity pools were supplied or discovered.",
            result.warnings,
        )

    def test_analyze_with_empty_pool_iterable_returns_empty_analysis(self):
        result = self.analyzer.analyze(
            TOKEN_ADDRESS,
            pool_addresses=[],
        )

        self.assertEqual(
            result.pools,
            (),
        )

        self.assertFalse(
            result.has_liquidity,
        )

    # ========================================================================
    # Analyze - pool discovery
    # ========================================================================

    def test_analyze_ignores_non_matching_pool(self):
        self.analyzer._inspect_pool = MagicMock(
            return_value=None,
        )

        result = self.analyzer.analyze(
            TOKEN_ADDRESS,
            pool_addresses=[
                POOL_ADDRESS,
            ],
        )

        self.assertEqual(
            result.pools,
            (),
        )

        self.assertFalse(
            result.has_liquidity,
        )

        self.analyzer._inspect_pool.assert_called_once()

    def test_analyze_includes_valid_pool(self):
        pool = LiquidityPool(
            pool_address=POOL_ADDRESS,
            token_address=TOKEN_ADDRESS,
            paired_token=PAIRED_TOKEN_ADDRESS,
            reserve_token=Decimal("1000"),
            reserve_paired=Decimal("2"),
            liquidity_usd=None,
        )

        self.analyzer._inspect_pool = MagicMock(
            return_value=pool,
        )

        result = self.analyzer.analyze(
            TOKEN_ADDRESS,
            pool_addresses=[
                POOL_ADDRESS,
            ],
        )

        self.assertEqual(
            result.pools,
            (pool,),
        )

        self.assertEqual(
            result.liquidity_pool_count,
            1,
        )

        self.assertFalse(
            result.has_liquidity,
        )

        self.assertIsNone(
            result.total_liquidity_usd,
        )

    def test_analyze_passes_each_pool_to_inspector(self):
        pool_one = "0x2222222222222222222222222222222222222222"
        pool_two = "0x4444444444444444444444444444444444444444"

        self.analyzer._inspect_pool = MagicMock(
            return_value=None,
        )

        self.analyzer.analyze(
            TOKEN_ADDRESS,
            pool_addresses=[
                pool_one,
                pool_two,
            ],
        )

        self.assertEqual(
            self.analyzer._inspect_pool.call_count,
            2,
        )

    # ========================================================================
    # Pool inspection
    # ========================================================================

    def test_inspect_pool_returns_none_for_non_contract(self):
        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            return_value=bytes(),
        ):
            result = self.analyzer._inspect_pool(
                token_address=TOKEN_ADDRESS,
                pool_address=POOL_ADDRESS,
            )

        self.assertIsNone(
            result,
        )

    def test_inspect_pool_rpc_failure_becomes_liquidity_rpc_error(self):
        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            side_effect=Web3Exception(
                "RPC unavailable",
            ),
        ):
            with self.assertRaises(
                LiquidityRPCError,
            ):
                self.analyzer._inspect_pool(
                    token_address=TOKEN_ADDRESS,
                    pool_address=POOL_ADDRESS,
                )

    def test_inspect_pool_unexpected_code_error_becomes_liquidity_rpc_error(self):
        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            side_effect=RuntimeError(
                "unexpected",
            ),
        ):
            with self.assertRaises(
                LiquidityRPCError,
            ):
                self.analyzer._inspect_pool(
                    token_address=TOKEN_ADDRESS,
                    pool_address=POOL_ADDRESS,
                )

    def test_inspect_pool_returns_none_when_pair_calls_fail(self):
        mock_contract = MagicMock()

        mock_contract.functions.token0().call.side_effect = (
            Exception("not a V2 pair")
        )

        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            return_value=bytes.fromhex("60016002"),
        ), patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._inspect_pool(
                token_address=TOKEN_ADDRESS,
                pool_address=POOL_ADDRESS,
            )

        self.assertIsNone(
            result,
        )

    def test_inspect_pool_rejects_pool_that_does_not_contain_token(self):
        mock_contract = MagicMock()

        mock_contract.functions.token0().call.return_value = (
            PAIRED_TOKEN_ADDRESS
        )

        mock_contract.functions.token1().call.return_value = (
            "0x4444444444444444444444444444444444444444"
        )

        mock_contract.functions.getReserves().call.return_value = (
            1000,
            2000,
            123,
        )

        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            return_value=bytes.fromhex("60016002"),
        ), patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._inspect_pool(
                token_address=TOKEN_ADDRESS,
                pool_address=POOL_ADDRESS,
            )

        self.assertIsNone(
            result,
        )

    
    def test_inspect_pool_identifies_token_as_token1(self):
        mock_contract = MagicMock()

        mock_contract.functions.token0().call.return_value = (
            PAIRED_TOKEN_ADDRESS
        )

        mock_contract.functions.token1().call.return_value = (
            TOKEN_ADDRESS
        )

        mock_contract.functions.getReserves().call.return_value = (
            2_000_000,
            1_000_000,
            123,
        )

        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            return_value=bytes.fromhex("60016002"),
        ), patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            side_effect=(
                6,   # TOKEN_ADDRESS
                18,  # PAIRED_TOKEN_ADDRESS
            ),
        ):
            result = self.analyzer._inspect_pool(
                token_address=TOKEN_ADDRESS,
                pool_address=POOL_ADDRESS,
            )

        self.assertIsNotNone(result)

        self.assertEqual(
            result.paired_token,
            Web3.to_checksum_address(
                PAIRED_TOKEN_ADDRESS,
            ),
        )

        # token1 reserve:
        # 1,000,000 / 10^6 = 1
        self.assertEqual(
            result.reserve_token,
            Decimal("1"),
        )

        # token0 reserve:
        # 2,000,000 / 10^18 = 0.000000000002
        self.assertEqual(
            result.reserve_paired,
            Decimal("0.000000000002"),
        )



    # ========================================================================
    # Decimals
    # ========================================================================

    def test_read_decimals_returns_valid_value(self):
        mock_contract = MagicMock()

        mock_contract.functions.decimals().call.return_value = 6

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_decimals(
                TOKEN_ADDRESS,
            )

        self.assertEqual(
            result,
            6,
        )

    def test_read_decimals_defaults_to_18_on_failure(self):
        mock_contract = MagicMock()

        mock_contract.functions.decimals().call.side_effect = (
            Exception("metadata failure")
        )

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_decimals(
                TOKEN_ADDRESS,
            )

        self.assertEqual(
            result,
            18,
        )

    def test_read_decimals_rejects_values_above_255(self):
        mock_contract = MagicMock()

        mock_contract.functions.decimals().call.return_value = 256

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_decimals(
                TOKEN_ADDRESS,
            )

        self.assertEqual(
            result,
            18,
        )

    # ========================================================================
    # Burn/dead address handling
    # ========================================================================

    def test_dead_address_constant_contains_zero_address(self):
        self.assertIn(
            "0x0000000000000000000000000000000000000000",
            DEAD_ADDRESSES,
        )

    def test_dead_address_constant_contains_dead_address(self):
        self.assertIn(
            "0x000000000000000000000000000000000000dead",
            DEAD_ADDRESSES,
        )

    # ========================================================================
    # Existing result semantics
    # ========================================================================

    def test_analysis_defaults_are_safe(self):
        result = LiquidityAnalysis(
            token_address=TOKEN_ADDRESS,
        )

        self.assertEqual(
            result.pools,
            (),
        )

        self.assertEqual(
            result.liquidity_pool_count,
            0,
        )

        self.assertFalse(
            result.has_liquidity,
        )

        self.assertIsNone(
            result.total_liquidity_usd,
        )

        self.assertIsNone(
            result.deepest_pool_address,
        )

        self.assertIsNone(
            result.liquidity_concentration_percentage,
        )

        self.assertEqual(
            result.warnings,
            (),
        )
