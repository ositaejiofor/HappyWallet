from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase
from web3 import Web3
from web3.exceptions import Web3Exception

from apps.token_scanner.services.contract import (
    ContractAnalysis,
    ContractRPCError,
    EVMContractAnalyzer,
    InvalidContractAddressError,
    SELECTOR_ALLOWANCE,
    SELECTOR_APPROVE,
    SELECTOR_BALANCE_OF,
    SELECTOR_BLACKLIST,
    SELECTOR_MINT,
    SELECTOR_OWNER,
    SELECTOR_PAUSE,
    SELECTOR_TOTAL_SUPPLY,
    SELECTOR_TRANSFER,
    SELECTOR_TRANSFER_FROM,
)


RPC_URL = "http://example-rpc.invalid"
VALID_ADDRESS = "0x1111111111111111111111111111111111111111"


class EVMContractAnalyzerTests(SimpleTestCase):
    """Tests for the read-only EVM contract analyzer."""

    def setUp(self):
        self.analyzer = EVMContractAnalyzer(RPC_URL)

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
            EVMContractAnalyzer("")

    def test_whitespace_rpc_url_is_rejected(self):
        with self.assertRaises(ValueError):
            EVMContractAnalyzer("   ")

    # ========================================================================
    # Address validation
    # ========================================================================

    def test_invalid_address_is_rejected(self):
        with self.assertRaises(InvalidContractAddressError):
            self.analyzer._validate_address(
                "not-an-address",
            )

    def test_empty_address_is_rejected(self):
        with self.assertRaises(InvalidContractAddressError):
            self.analyzer._validate_address("")

    def test_non_string_address_is_rejected(self):
        with self.assertRaises(InvalidContractAddressError):
            self.analyzer._validate_address(None)

    def test_valid_address_is_checksummed(self):
        result = self.analyzer._validate_address(
            VALID_ADDRESS,
        )

        self.assertEqual(
            result,
            Web3.to_checksum_address(
                VALID_ADDRESS,
            ),
        )

    # ========================================================================
    # Bytecode normalization
    # ========================================================================

    def test_normalize_code_removes_prefix(self):
        self.assertEqual(
            EVMContractAnalyzer._normalize_code(
                "0xABCDEF",
            ),
            "abcdef",
        )

    def test_normalize_code_handles_plain_hex(self):
        self.assertEqual(
            EVMContractAnalyzer._normalize_code(
                "ABCDEF",
            ),
            "abcdef",
        )

    def test_normalize_code_handles_non_string(self):
        self.assertEqual(
            EVMContractAnalyzer._normalize_code(None),
            "",
        )

    # ========================================================================
    # Selector detection
    # ========================================================================

    def test_selector_detection_is_case_insensitive(self):
        self.assertTrue(
            EVMContractAnalyzer._contains_selector(
                "0x1234ABCDEF",
                "abcdef",
            )
        )

    def test_selector_detection_returns_false_when_missing(self):
        self.assertFalse(
            EVMContractAnalyzer._contains_selector(
                "12345678",
                "abcdef",
            )
        )

    # ========================================================================
    # Bytecode size
    # ========================================================================

    def test_bytecode_size_is_calculated_in_bytes(self):
        self.assertEqual(
            EVMContractAnalyzer._bytecode_size(
                "0x60016002",
            ),
            4,
        )

    def test_empty_bytecode_has_zero_size(self):
        self.assertEqual(
            EVMContractAnalyzer._bytecode_size(""),
            0,
        )

    def test_invalid_bytecode_has_zero_size(self):
        self.assertEqual(
            EVMContractAnalyzer._bytecode_size(
                "not-valid-hex",
            ),
            0,
        )

    # ========================================================================
    # Contract detection
    # ========================================================================

    def test_non_contract_address_returns_non_contract_analysis(self):
        with patch.object(
            self.analyzer,
            "_get_code",
            return_value="0x",
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertFalse(
            result.is_contract,
        )

        self.assertFalse(
            result.is_erc20_like,
        )

        self.assertEqual(
            result.raw_code_size,
            0,
        )

        self.assertIn(
            "Address does not contain contract bytecode.",
            result.warnings,
        )

    # ========================================================================
    # ERC-20 detection
    # ========================================================================

    def test_contract_analysis_detects_erc20_selectors(self):
        selectors = (
            SELECTOR_TOTAL_SUPPLY,
            SELECTOR_BALANCE_OF,
            SELECTOR_TRANSFER,
            SELECTOR_TRANSFER_FROM,
            SELECTOR_APPROVE,
            SELECTOR_ALLOWANCE,
        )

        code = "0x" + "".join(selectors)

        with patch.object(
            self.analyzer,
            "_get_code",
            return_value=code,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            return_value=18,
        ), patch.object(
            self.analyzer,
            "_read_string_function",
            side_effect=["Happy Token", "HAPPY"],
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertTrue(
            result.is_contract,
        )

        self.assertTrue(
            result.is_erc20_like,
        )

        self.assertEqual(
            result.decimals,
            18,
        )

        self.assertEqual(
            result.name,
            "Happy Token",
        )

        self.assertEqual(
            result.symbol,
            "HAPPY",
        )

    def test_incomplete_erc20_interface_is_not_erc20_like(self):
        code = "0x" + SELECTOR_TRANSFER

        with patch.object(
            self.analyzer,
            "_get_code",
            return_value=code,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            return_value=None,
        ), patch.object(
            self.analyzer,
            "_read_string_function",
            return_value="",
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertTrue(
            result.is_contract,
        )

        self.assertFalse(
            result.is_erc20_like,
        )

        self.assertIn(
            "Contract does not expose the expected ERC-20 function set.",
            result.warnings,
        )

    # ========================================================================
    # Privileged function detection
    # ========================================================================

    def test_contract_analysis_detects_owner(self):
        code = "0x" + SELECTOR_OWNER

        with patch.object(
            self.analyzer,
            "_get_code",
            return_value=code,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            return_value=None,
        ), patch.object(
            self.analyzer,
            "_read_string_function",
            return_value="",
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertTrue(
            result.owner_function_detected,
        )

        self.assertTrue(
            any(
                "owner()" in warning
                for warning in result.warnings
            )
        )

    def test_contract_analysis_detects_mint(self):
        code = "0x" + SELECTOR_MINT

        with patch.object(
            self.analyzer,
            "_get_code",
            return_value=code,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            return_value=None,
        ), patch.object(
            self.analyzer,
            "_read_string_function",
            return_value="",
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertTrue(
            result.mint_function_detected,
        )

        self.assertTrue(
            result.unlimited_mint_detected,
        )

        self.assertIn(
            "A mint-related function selector was detected. "
            "Manual source-code review is required to determine "
            "whether supply can be increased.",
            result.warnings,
        )

    def test_contract_analysis_detects_blacklist(self):
        code = "0x" + SELECTOR_BLACKLIST

        with patch.object(
            self.analyzer,
            "_get_code",
            return_value=code,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            return_value=None,
        ), patch.object(
            self.analyzer,
            "_read_string_function",
            return_value="",
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertTrue(
            result.blacklist_function_detected,
        )

        self.assertTrue(
            any(
                "blacklist-related" in warning
                for warning in result.warnings
            )
        )

    def test_contract_analysis_detects_pause(self):
        code = "0x" + SELECTOR_PAUSE

        with patch.object(
            self.analyzer,
            "_get_code",
            return_value=code,
        ), patch.object(
            self.analyzer,
            "_read_decimals",
            return_value=None,
        ), patch.object(
            self.analyzer,
            "_read_string_function",
            return_value="",
        ):
            result = self.analyzer.analyze(
                VALID_ADDRESS,
            )

        self.assertTrue(
            result.pause_function_detected,
        )

        self.assertTrue(
            any(
                "Pause/unpause" in warning
                for warning in result.warnings
            )
        )

    # ========================================================================
    # Metadata
    # ========================================================================

    def test_decimals_failure_is_non_fatal(self):
        mock_contract = MagicMock()

        mock_contract.functions.decimals().call.side_effect = Exception(
            "RPC failure",
        )

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_decimals(
                VALID_ADDRESS,
            )

        self.assertIsNone(
            result,
        )

    def test_invalid_decimals_are_rejected(self):
        mock_contract = MagicMock()

        mock_contract.functions.decimals().call.return_value = 999

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_decimals(
                VALID_ADDRESS,
            )

        self.assertIsNone(
            result,
        )

    def test_name_metadata_failure_is_non_fatal(self):
        mock_contract = MagicMock()

        mock_contract.functions.name().call.side_effect = Exception(
            "metadata failure",
        )

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_string_function(
                VALID_ADDRESS,
                "name",
            )

        self.assertEqual(
            result,
            "",
        )

    def test_symbol_metadata_failure_is_non_fatal(self):
        mock_contract = MagicMock()

        mock_contract.functions.symbol().call.side_effect = Exception(
            "metadata failure",
        )

        with patch.object(
            self.analyzer.web3.eth,
            "contract",
            return_value=mock_contract,
        ):
            result = self.analyzer._read_string_function(
                VALID_ADDRESS,
                "symbol",
            )

        self.assertEqual(
            result,
            "",
        )

    def test_unsupported_metadata_function_is_rejected(self):
        with self.assertRaises(ValueError):
            self.analyzer._read_string_function(
                VALID_ADDRESS,
                "decimals",
            )

    # ========================================================================
    # RPC errors
    # ========================================================================

    def test_rpc_failure_becomes_contract_rpc_error(self):
        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            side_effect=Web3Exception(
                "RPC unavailable",
            ),
        ):
            with self.assertRaises(ContractRPCError):
                self.analyzer._get_code(
                    VALID_ADDRESS,
                )

    def test_unexpected_code_error_becomes_contract_rpc_error(self):
        with patch.object(
            self.analyzer.web3.eth,
            "get_code",
            side_effect=RuntimeError(
                "unexpected",
            ),
        ):
            with self.assertRaises(ContractRPCError):
                self.analyzer._get_code(
                    VALID_ADDRESS,
                )

    # ========================================================================
    # Result object
    # ========================================================================

    def test_contract_warning_count(self):
        result = ContractAnalysis(
            address=VALID_ADDRESS,
            is_contract=True,
            warnings=(
                "warning-a",
                "warning-b",
            ),
        )

        self.assertEqual(
            result.contract_warning_count,
            2,
        )

    def test_high_risk_contract_classification_from_mint(self):
        result = ContractAnalysis(
            address=VALID_ADDRESS,
            is_contract=True,
            unlimited_mint_detected=True,
        )

        self.assertTrue(
            result.is_high_risk,
        )

    def test_high_risk_contract_classification_from_blacklist(self):
        result = ContractAnalysis(
            address=VALID_ADDRESS,
            is_contract=True,
            blacklist_function_detected=True,
        )

        self.assertTrue(
            result.is_high_risk,
        )

    def test_high_risk_contract_classification_from_fee_control(self):
        result = ContractAnalysis(
            address=VALID_ADDRESS,
            is_contract=True,
            fee_control_detected=True,
        )

        self.assertTrue(
            result.is_high_risk,
        )

    def test_normal_contract_is_not_high_risk(self):
        result = ContractAnalysis(
            address=VALID_ADDRESS,
            is_contract=True,
            is_erc20_like=True,
        )

        self.assertFalse(
            result.is_high_risk,
        )
