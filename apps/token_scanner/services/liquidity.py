"""
HappyWallet Token Scanner - Liquidity Analysis.

Read-only DEX liquidity analysis for EVM tokens.

Security rules:
    - Never request private keys.
    - Never sign transactions.
    - Never approve token spending.
    - Never execute swaps.
    - Never add or remove liquidity.

This module only reads public blockchain state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

from web3 import Web3
from web3.exceptions import Web3Exception


# ============================================================================
# Constants
# ============================================================================

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# Common burn/dead addresses.
DEAD_ADDRESSES = {
    ZERO_ADDRESS.lower(),
    "0x000000000000000000000000000000000000dead",
}

# Uniswap V2-style PairCreated event:
#
# PairCreated(address indexed token0,
#             address indexed token1,
#             address pair,
#             uint256)
#
# keccak256("PairCreated(address,address,address,uint256)")
PAIR_CREATED_TOPIC = (
    "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
)

# ERC-20 balanceOf(address)
BALANCE_OF_SELECTOR = "70a08231"

# ERC-20 decimals()
DECIMALS_SELECTOR = "313ce567"


# ============================================================================
# Exceptions
# ============================================================================


class LiquidityAnalysisError(Exception):
    """Base exception for liquidity analysis."""


class InvalidLiquidityAddressError(LiquidityAnalysisError):
    """Raised when an address is invalid."""


class LiquidityRPCError(LiquidityAnalysisError):
    """Raised when blockchain RPC access fails."""


# ============================================================================
# Result objects
# ============================================================================


@dataclass(frozen=True)
class LiquidityPool:
    """
    Represents a discovered liquidity pool.

    This object stores public analytical information only.
    """

    pool_address: str

    token_address: str

    paired_token: str = ""

    dex_name: str = ""

    reserve_token: Decimal | None = None
    reserve_paired: Decimal | None = None

    liquidity_usd: Decimal | None = None

    is_active: bool = True

    is_burn_address: bool = False

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LiquidityAnalysis:
    """
    Aggregate liquidity analysis for a token.
    """

    token_address: str

    pools: tuple[LiquidityPool, ...] = field(default_factory=tuple)

    total_liquidity_usd: Decimal | None = None

    deepest_pool_address: str | None = None

    liquidity_pool_count: int = 0

    has_liquidity: bool = False

    liquidity_concentration_percentage: Decimal | None = None

    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_thin_liquidity(self) -> bool:
        """
        Return True when known liquidity is extremely small.

        This is a heuristic and should not be treated as a trading signal.
        """

        if self.total_liquidity_usd is None:
            return False

        return self.total_liquidity_usd < Decimal("25000")


# ============================================================================
# Analyzer
# ============================================================================


class EVMLiquidityAnalyzer:
    """
    Read-only liquidity analyzer for EVM tokens.

    This class intentionally does not execute transactions.

    Parameters
    ----------
    rpc_url:
        Ethereum-compatible JSON-RPC endpoint.

    timeout:
        HTTP timeout in seconds.
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
        token_address: str,
        *,
        pool_addresses: Iterable[str] | None = None,
    ) -> LiquidityAnalysis:
        """
        Analyze known liquidity pools for a token.

        Parameters
        ----------
        token_address:
            ERC-20 token contract.

        pool_addresses:
            Optional iterable of known pool addresses.

        Notes
        -----
        This first implementation intentionally accepts known pool
        addresses rather than pretending that arbitrary DEX discovery
        is complete.

        A later discovery layer can supply pools from:
            - factory events
            - indexed DEX data
            - configured factory contracts
            - external market-data providers
        """

        token = self._validate_address(token_address)

        normalized_pools: list[str] = []

        if pool_addresses is not None:
            for pool_address in pool_addresses:
                normalized_pools.append(
                    self._validate_address(pool_address)
                )

        pools: list[LiquidityPool] = []
        warnings: list[str] = []

        for pool_address in normalized_pools:
            pool = self._inspect_pool(
                token_address=token,
                pool_address=pool_address,
            )

            if pool is not None:
                pools.append(pool)

        if not pools:
            warnings.append(
                "No known liquidity pools were supplied or discovered."
            )

            return LiquidityAnalysis(
                token_address=token,
                pools=tuple(),
                total_liquidity_usd=None,
                deepest_pool_address=None,
                liquidity_pool_count=0,
                has_liquidity=False,
                warnings=tuple(warnings),
            )

        pools_with_liquidity = [
            pool
            for pool in pools
            if pool.liquidity_usd is not None
            and pool.liquidity_usd > Decimal("0")
        ]

        total_liquidity: Decimal | None = None

        if pools_with_liquidity:
            total_liquidity = sum(
                (
                    pool.liquidity_usd
                    for pool in pools_with_liquidity
                    if pool.liquidity_usd is not None
                ),
                Decimal("0"),
            )

        deepest_pool: LiquidityPool | None = None

        if pools_with_liquidity:
            deepest_pool = max(
                pools_with_liquidity,
                key=lambda pool: pool.liquidity_usd
                or Decimal("0"),
            )

        concentration: Decimal | None = None

        if (
            total_liquidity
            and deepest_pool is not None
            and deepest_pool.liquidity_usd is not None
        ):
            concentration = (
                deepest_pool.liquidity_usd
                / total_liquidity
                * Decimal("100")
            )

        if (
            total_liquidity is not None
            and total_liquidity < Decimal("25000")
        ):
            warnings.append(
                "Known liquidity is below $25,000. "
                "Execution may experience significant slippage."
            )

        if (
            concentration is not None
            and concentration >= Decimal("90")
            and len(pools) > 1
        ):
            warnings.append(
                "Most known liquidity is concentrated in one pool."
            )

        burn_pools = [
            pool
            for pool in pools
            if pool.is_burn_address
        ]

        if burn_pools:
            warnings.append(
                "A supplied pool address matches a known burn/dead "
                "address and should be reviewed."
            )

        return LiquidityAnalysis(
            token_address=token,
            pools=tuple(pools),
            total_liquidity_usd=total_liquidity,
            deepest_pool_address=(
                deepest_pool.pool_address
                if deepest_pool is not None
                else None
            ),
            liquidity_pool_count=len(pools),
            has_liquidity=bool(pools_with_liquidity),
            liquidity_concentration_percentage=concentration,
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------------
    # Pool inspection
    # ------------------------------------------------------------------

    def _inspect_pool(
        self,
        *,
        token_address: str,
        pool_address: str,
    ) -> LiquidityPool | None:
        """
        Inspect a known V2-style liquidity pool.

        The pool is queried using a minimal ABI.

        We intentionally avoid assuming every DEX uses the same pool
        architecture.
        """

        pool_address = self._validate_address(pool_address)

        try:
            code = self.web3.eth.get_code(pool_address)

        except Web3Exception as exc:
            raise LiquidityRPCError(
                "Unable to retrieve liquidity-pool bytecode."
            ) from exc

        except Exception as exc:
            raise LiquidityRPCError(
                "Unexpected error while retrieving liquidity-pool "
                "bytecode."
            ) from exc

        if not code or code.hex() in {"0x", ""}:
            return None

        pair_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "token0",
                "outputs": [
                    {
                        "name": "",
                        "type": "address",
                    }
                ],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "token1",
                "outputs": [
                    {
                        "name": "",
                        "type": "address",
                    }
                ],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "getReserves",
                "outputs": [
                    {
                        "name": "reserve0",
                        "type": "uint112",
                    },
                    {
                        "name": "reserve1",
                        "type": "uint112",
                    },
                    {
                        "name": "blockTimestampLast",
                        "type": "uint32",
                    },
                ],
                "stateMutability": "view",
                "type": "function",
            },
        ]

        try:
            pool = self.web3.eth.contract(
                address=pool_address,
                abi=pair_abi,
            )

            token0 = self.web3.to_checksum_address(
                pool.functions.token0().call()
            )

            token1 = self.web3.to_checksum_address(
                pool.functions.token1().call()
            )

            reserve0, reserve1, _ = (
                pool.functions.getReserves().call()
            )

        except Exception:
            # A pool using another architecture should not crash
            # the entire scanner.
            return None

        token_lower = token_address.lower()

        if token0.lower() == token_lower:
            token_reserve_raw = reserve0
            paired_reserve_raw = reserve1
            paired_token = token1

        elif token1.lower() == token_lower:
            token_reserve_raw = reserve1
            paired_reserve_raw = reserve0
            paired_token = token0

        else:
            # This pool does not contain the token being analyzed.
            return None

        token_decimals = self._read_decimals(
            token_address,
        )

        paired_decimals = self._read_decimals(
            paired_token,
        )

        token_reserve = self._normalize_reserve(
            token_reserve_raw,
            token_decimals,
        )

        paired_reserve = self._normalize_reserve(
            paired_reserve_raw,
            paired_decimals,
        )

        is_dead = (
            pool_address.lower()
            in DEAD_ADDRESSES
        )

        return LiquidityPool(
            pool_address=pool_address,
            token_address=token_address,
            paired_token=paired_token,
            dex_name="unknown",
            reserve_token=token_reserve,
            reserve_paired=paired_reserve,
            liquidity_usd=None,
            is_active=not is_dead,
            is_burn_address=is_dead,
            metadata={
                "pool_type": "uniswap_v2_compatible",
            },
        )

    # ------------------------------------------------------------------
    # ERC-20 decimals
    # ------------------------------------------------------------------

    def _read_decimals(
        self,
        token_address: str,
    ) -> int:
        """
        Read ERC-20 decimals.

        Defaults to 18 if the token does not expose a usable value.

        The default is only used for reserve normalization; it is not
        persisted as a verified token property.
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
                address=token_address,
                abi=abi,
            )

            value = int(
                contract.functions.decimals().call()
            )

            if 0 <= value <= 255:
                return value

        except Exception:
            pass

        return 18

    # ------------------------------------------------------------------
    # Numeric helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_reserve(
        raw_value: int,
        decimals: int,
    ) -> Decimal:
        """
        Convert an integer token reserve into human-readable units.
        """

        if raw_value < 0:
            raise ValueError(
                "Reserve cannot be negative."
            )

        if decimals < 0:
            raise ValueError(
                "Decimals cannot be negative."
            )

        return Decimal(raw_value) / (
            Decimal(10) ** decimals
        )

    # ------------------------------------------------------------------
    # Address validation
    # ------------------------------------------------------------------

    def _validate_address(
        self,
        address: str,
    ) -> str:
        """
        Validate and checksum an EVM address.
        """

        if not isinstance(address, str):
            raise InvalidLiquidityAddressError(
                "Address must be a string."
            )

        address = address.strip()

        if not address:
            raise InvalidLiquidityAddressError(
                "Address is required."
            )

        if not self.web3.is_address(address):
            raise InvalidLiquidityAddressError(
                f"Invalid EVM address: {address}"
            )

        return self.web3.to_checksum_address(address)