"""
HappyWallet Token Scanner - EVM Contract Analysis.

This module performs READ-ONLY analysis of token contracts.

Security rules:
    - Never request or handle private keys.
    - Never handle seed phrases.
    - Never sign transactions.
    - Never submit transactions.
    - Never approve token spending.
    - Never automatically buy or sell tokens.

The scanner only inspects publicly available blockchain state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from web3 import Web3
from web3.exceptions import Web3Exception


# ---------------------------------------------------------------------------
# ERC-20 function selectors
# ---------------------------------------------------------------------------
#
# These are the first four bytes of the Keccak-256 function signatures.
#
# They allow us to perform lightweight bytecode inspection without requiring
# a complete ABI.
# ---------------------------------------------------------------------------

SELECTOR_TOTAL_SUPPLY = "18160ddd"
SELECTOR_BALANCE_OF = "70a08231"
SELECTOR_TRANSFER = "a9059cbb"
SELECTOR_TRANSFER_FROM = "23b872dd"
SELECTOR_APPROVE = "095ea7b3"
SELECTOR_ALLOWANCE = "dd62ed3e"
SELECTOR_DECIMALS = "313ce567"
SELECTOR_SYMBOL = "95d89b41"
SELECTOR_NAME = "06fdde03"


# ---------------------------------------------------------------------------
# Common function selectors associated with privileged token controls.
# ---------------------------------------------------------------------------

SELECTOR_MINT = "40c10f19"              # mint(address,uint256)
SELECTOR_BURN = "42966c68"              # burn(uint256)
SELECTOR_PAUSE = "8456cb59"             # pause()
SELECTOR_UNPAUSE = "3f4ba83a"           # unpause()

SELECTOR_BLACKLIST = "f9f92be4"         # blacklist(address)
SELECTOR_UNBLACKLIST = "1d9f1f7f"       # unBlacklist(address)

SELECTOR_SET_FEES = "b6f9de95"          # common set-fees pattern
SELECTOR_SET_TAX = "e3a3d3e8"           # common set-tax pattern

SELECTOR_OWNER = "8da5cb5b"             # owner()
SELECTOR_RENOUNCE_OWNERSHIP = "715018a6" # renounceOwnership()


# ---------------------------------------------------------------------------
# Analysis result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContractAnalysis:
    """
    Result of read-only contract analysis.

    This object deliberately contains analytical information only.
    """

    address: str
    is_contract: bool

    verified: bool = False

    is_erc20_like: bool = False

    decimals: int | None = None
    name: str = ""
    symbol: str = ""

    owner_function_detected: bool = False

    mint_function_detected: bool = False
    unlimited_mint_detected: bool = False

    blacklist_function_detected: bool = False
    pause_function_detected: bool = False

    fee_control_detected: bool = False

    warnings: tuple[str, ...] = field(default_factory=tuple)

    raw_code_size: int = 0

    @property
    def contract_warning_count(self) -> int:
        """Return the number of generated warnings."""

        return len(self.warnings)

    @property
    def is_high_risk(self) -> bool:
        """
        Conservative contract-risk classification.

        This is NOT a financial prediction.
        """

        return (
            self.unlimited_mint_detected
            or self.blacklist_function_detected
            or self.fee_control_detected
        )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ContractAnalysisError(Exception):
    """Base exception for token contract analysis."""


class InvalidContractAddressError(ContractAnalysisError):
    """Raised when a supplied address is invalid."""


class ContractRPCError(ContractAnalysisError):
    """Raised when the blockchain RPC cannot be queried."""


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class EVMContractAnalyzer:
    """
    Read-only analyzer for EVM token contracts.

    Parameters
    ----------
    rpc_url:
        Ethereum-compatible JSON-RPC endpoint.

    timeout:
        HTTP request timeout in seconds.

    Notes
    -----
    This class intentionally does not contain any transaction-sending
    functionality.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        timeout: float = 10.0,
    ) -> None:
        if not isinstance(rpc_url, str) or not rpc_url.strip():
            raise ValueError("rpc_url must be a non-empty string.")

        self.rpc_url = rpc_url.strip()

        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={
                    "timeout": timeout,
                },
            )
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        address: str,
        *,
        verified: bool = False,
    ) -> ContractAnalysis:
        """
        Perform read-only analysis of an EVM contract.

        Parameters
        ----------
        address:
            Token contract address.

        verified:
            Whether source-code verification has already been established
            by an external verification provider.

        Returns
        -------
        ContractAnalysis
        """

        checksum_address = self._validate_address(address)

        code = self._get_code(checksum_address)

        if not code or code in ("0x", "0X"):
            return ContractAnalysis(
                address=checksum_address,
                is_contract=False,
                verified=verified,
                warnings=(
                    "Address does not contain contract bytecode.",
                ),
            )

        code_hex = self._normalize_code(code)

        warnings: list[str] = []

        decimals = self._read_decimals(checksum_address)
        name = self._read_string_function(
            checksum_address,
            "name",
        )
        symbol = self._read_string_function(
            checksum_address,
            "symbol",
        )

        has_total_supply = self._contains_selector(
            code_hex,
            SELECTOR_TOTAL_SUPPLY,
        )

        has_balance_of = self._contains_selector(
            code_hex,
            SELECTOR_BALANCE_OF,
        )

        has_transfer = self._contains_selector(
            code_hex,
            SELECTOR_TRANSFER,
        )

        has_transfer_from = self._contains_selector(
            code_hex,
            SELECTOR_TRANSFER_FROM,
        )

        has_approve = self._contains_selector(
            code_hex,
            SELECTOR_APPROVE,
        )

        has_allowance = self._contains_selector(
            code_hex,
            SELECTOR_ALLOWANCE,
        )

        is_erc20_like = all(
            (
                has_total_supply,
                has_balance_of,
                has_transfer,
                has_transfer_from,
                has_approve,
                has_allowance,
            )
        )

        owner_detected = self._contains_selector(
            code_hex,
            SELECTOR_OWNER,
        )

        mint_detected = self._contains_selector(
            code_hex,
            SELECTOR_MINT,
        )

        blacklist_detected = (
            self._contains_selector(
                code_hex,
                SELECTOR_BLACKLIST,
            )
            or self._contains_selector(
                code_hex,
                SELECTOR_UNBLACKLIST,
            )
        )

        pause_detected = (
            self._contains_selector(
                code_hex,
                SELECTOR_PAUSE,
            )
            or self._contains_selector(
                code_hex,
                SELECTOR_UNPAUSE,
            )
        )

        fee_control_detected = (
            self._contains_selector(
                code_hex,
                SELECTOR_SET_FEES,
            )
            or self._contains_selector(
                code_hex,
                SELECTOR_SET_TAX,
            )
        )

        # --------------------------------------------------------------
        # Risk warnings
        # --------------------------------------------------------------

        if not is_erc20_like:
            warnings.append(
                "Contract does not expose the expected ERC-20 function set."
            )

        if mint_detected:
            warnings.append(
                "A mint-related function selector was detected. "
                "Manual source-code review is required to determine "
                "whether supply can be increased."
            )

        if blacklist_detected:
            warnings.append(
                "A blacklist-related function selector was detected."
            )

        if fee_control_detected:
            warnings.append(
                "A fee/tax control function selector was detected."
            )

        if pause_detected:
            warnings.append(
                "Pause/unpause functionality was detected."
            )

        if owner_detected:
            warnings.append(
                "An owner() function selector was detected. "
                "Privileged ownership should be reviewed."
            )

        return ContractAnalysis(
            address=checksum_address,
            is_contract=True,
            verified=verified,
            is_erc20_like=is_erc20_like,
            decimals=decimals,
            name=name,
            symbol=symbol,
            owner_function_detected=owner_detected,
            mint_function_detected=mint_detected,
            unlimited_mint_detected=mint_detected,
            blacklist_function_detected=blacklist_detected,
            pause_function_detected=pause_detected,
            fee_control_detected=fee_control_detected,
            warnings=tuple(warnings),
            raw_code_size=self._bytecode_size(code_hex),
        )

    # ------------------------------------------------------------------
    # Address handling
    # ------------------------------------------------------------------

    def _validate_address(self, address: str) -> str:
        """
        Validate and checksum an EVM address.
        """

        if not isinstance(address, str):
            raise InvalidContractAddressError(
                "Contract address must be a string."
            )

        address = address.strip()

        if not address:
            raise InvalidContractAddressError(
                "Contract address is required."
            )

        if not self.web3.is_address(address):
            raise InvalidContractAddressError(
                f"Invalid EVM contract address: {address}"
            )

        return self.web3.to_checksum_address(address)

    # ------------------------------------------------------------------
    # Blockchain RPC
    # ------------------------------------------------------------------

    def _get_code(self, address: str) -> str:
        """
        Retrieve deployed bytecode using eth_getCode.
        """

        try:
            return self.web3.eth.get_code(address).hex()

        except Web3Exception as exc:
            raise ContractRPCError(
                "Unable to retrieve contract bytecode."
            ) from exc

        except Exception as exc:
            raise ContractRPCError(
                "Unexpected error while retrieving contract bytecode."
            ) from exc

    # ------------------------------------------------------------------
    # ERC-20 metadata
    # ------------------------------------------------------------------

    def _read_decimals(
        self,
        address: str,
    ) -> int | None:
        """
        Read ERC-20 decimals through a minimal ABI.

        Returns None if the token does not expose a usable value.
        """

        abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [
                    {
                        "name": "",
                        "type": "uint8",
                    }
                ],
                "stateMutability": "view",
                "type": "function",
            }
        ]

        try:
            contract = self.web3.eth.contract(
                address=address,
                abi=abi,
            )

            value = contract.functions.decimals().call()

            if 0 <= int(value) <= 255:
                return int(value)

        except Exception:
            pass

        return None

    def _read_string_function(
        self,
        address: str,
        function_name: str,
    ) -> str:
        """
        Read a standard ERC-20 string function.

        Metadata retrieval failures are intentionally non-fatal because
        unusual but valid tokens may implement metadata differently.
        """

        if function_name not in {
            "name",
            "symbol",
        }:
            raise ValueError(
                "Only name and symbol are supported."
            )

        abi = [
            {
                "constant": True,
                "inputs": [],
                "name": function_name,
                "outputs": [
                    {
                        "name": "",
                        "type": "string",
                    }
                ],
                "stateMutability": "view",
                "type": "function",
            }
        ]

        try:
            contract = self.web3.eth.contract(
                address=address,
                abi=abi,
            )

            value = getattr(
                contract.functions,
                function_name,
            )().call()

            if isinstance(value, str):
                return value.strip()

        except Exception:
            pass

        return ""

    # ------------------------------------------------------------------
    # Bytecode helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_code(code: str) -> str:
        """
        Normalize bytecode to lowercase hexadecimal without 0x.
        """

        if not isinstance(code, str):
            return ""

        normalized = code.lower().strip()

        if normalized.startswith("0x"):
            normalized = normalized[2:]

        return normalized

    @staticmethod
    def _contains_selector(
        bytecode: str,
        selector: str,
    ) -> bool:
        """
        Determine whether a 4-byte function selector appears in bytecode.

        IMPORTANT:
        Selector presence is only a heuristic.

        It does NOT prove that:
            - the function is externally callable,
            - the function has the expected implementation,
            - the function is dangerous,
            - the owner can actually exploit it.

        Source-code and control-flow analysis are required for stronger
        conclusions.
        """

        return selector.lower().strip() in bytecode.lower()

    @staticmethod
    def _bytecode_size(code: str) -> int:
        """
        Return deployed bytecode size in bytes.
        """

        if not code:
            return 0

        normalized = code[2:] if code.startswith("0x") else code

        try:
            return len(bytes.fromhex(normalized))

        except ValueError:
            return 0