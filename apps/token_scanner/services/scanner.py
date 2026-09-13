"""
HappyWallet Token Scanner - Scanner Orchestrator.

Coordinates the read-only token discovery and analysis pipeline:

    Ethereum RPC
         |
         v
    DEX Factory
         |
         | PairCreated events
         v
    Real DEX Pools
         |
         | token0 / token1
         v
    Token Analysis
         |
         +--> Contract
         |
         +--> Liquidity
         |
         +--> Holders
         |
         +--> Demand
         |
         +--> Risk
         |
         v
    Human Inspection

Security rules
--------------
- Never request private keys.
- Never request seed phrases.
- Never sign transactions.
- Never submit transactions.
- Never approve token spending.
- Never execute swaps.
- Never automatically buy or sell tokens.
- Never fabricate token or market data.

This module only reads public blockchain state and orchestrates
read-only analysis services.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .contract import (
    ContractAnalysis,
    EVMContractAnalyzer,
)
from .demand import (
    DemandAnalysis,
    EVMDemandAnalyzer,
)
from .holders import (
    EVMHolderAnalyzer,
    HolderAnalysis,
)
from .liquidity import (
    EVMLiquidityAnalyzer,
    LiquidityAnalysis,
)
from .risk import (
    RiskAnalysis,
    TokenRiskAnalyzer,
)

from .dexy import (
    DEFAULT_LOG_CHUNK_SIZE as DEFAULT_DEX_LOG_CHUNK_SIZE,
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_POOLS,
    DexDiscoveryConfigurationError,
    DexDiscoveryResult,
    DexFactory,
    DexPool,
    EthereumDexDiscovery,
)

# Alchemy Free currently permits eth_getLogs requests over
# a maximum 10-block range for the token-analysis pipeline.
DEFAULT_TOKEN_LOG_CHUNK_SIZE = 10



# ============================================================================
# Result objects
# ============================================================================


@dataclass(frozen=True)
class TokenScanResult:
    """
    Complete read-only analysis of one EVM token.
    """

    token_address: str

    contract: ContractAnalysis

    liquidity: LiquidityAnalysis

    holders: HolderAnalysis

    demand: DemandAnalysis

    risk: RiskAnalysis

    warnings: tuple[str, ...] = field(
        default_factory=tuple,
    )

    @property
    def name(self) -> str:
        return self.contract.name

    @property
    def symbol(self) -> str:
        return self.contract.symbol

    @property
    def decimals(self) -> int | None:
        return self.contract.decimals

    @property
    def risk_score(self) -> int:
        return self.risk.score

    @property
    def is_contract(self) -> bool:
        return self.contract.is_contract

    @property
    def is_erc20_like(self) -> bool:
        return self.contract.is_erc20_like


@dataclass(frozen=True)
class DiscoveredTokenScan:
    """
    Analysis result for a token discovered through a real DEX pool.

    The pool_addresses field contains the actual discovered pools that
    contain this token.
    """

    token_address: str

    pool_addresses: tuple[str, ...]

    scan: TokenScanResult


@dataclass(frozen=True)
class TokenDiscoveryScanResult:
    """
    Complete result of a DEX discovery + token analysis operation.

    discovery:
        Raw read-only DEX discovery result.

    tokens:
        Successfully analyzed real token contracts.

    warnings:
        Aggregated discovery and token-analysis warnings.

    No object in this result represents an attempted transaction.
    """

    discovery: DexDiscoveryResult

    tokens: tuple[DiscoveredTokenScan, ...] = field(
        default_factory=tuple,
    )

    warnings: tuple[str, ...] = field(
        default_factory=tuple,
    )

    @property
    def pool_count(self) -> int:
        return self.discovery.pool_count

    @property
    def token_count(self) -> int:
        return len(self.tokens)

    @property
    def complete(self) -> bool:
        """
        Return whether discovery and analysis completed without
        truncation or discovery-level failure.

        Token-level analysis warnings do not automatically make the
        entire operation incomplete because some tokens may still have
        been successfully analyzed.
        """

        return self.discovery.complete


# ============================================================================
# Exceptions
# ============================================================================


class TokenScannerError(Exception):
    """Base exception for token scanner orchestration."""


class TokenDiscoveryScanError(TokenScannerError):
    """Raised when DEX discovery cannot be performed."""


# ============================================================================
# Scanner
# ============================================================================


class EVMTokenScanner:
    """
    High-level read-only EVM token scanner.

    There are two public workflows:

    1. scan()
       Analyze one known token address.

    2. discover_and_scan()
       Discover real DEX pools from configured factories and then
       analyze the real token contracts contained in those pools.

    The scanner never performs transaction execution.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        factories: Iterable[DexFactory] = (),
        timeout: float = 10.0,
        log_chunk_size: int = DEFAULT_TOKEN_LOG_CHUNK_SIZE,
        max_holder_events: int = 50_000,
        dex_log_chunk_size: int | None = None,
        dex_max_blocks: int = DEFAULT_MAX_BLOCKS,
        dex_max_pools: int = DEFAULT_MAX_POOLS,
    ) -> None:
        if not isinstance(
            rpc_url,
            str,
        ) or not rpc_url.strip():
            raise ValueError(
                "rpc_url must be a non-empty string."
            )

        if isinstance(
            timeout,
            bool,
        ) or not isinstance(
            timeout,
            (int, float),
        ) or timeout <= 0:
            raise ValueError(
                "timeout must be a positive number."
            )

        if isinstance(
            log_chunk_size,
            bool,
        ) or not isinstance(
            log_chunk_size,
            int,
        ) or log_chunk_size <= 0:
            raise ValueError(
                "log_chunk_size must be a positive integer."
            )

        if isinstance(
            max_holder_events,
            bool,
        ) or not isinstance(
            max_holder_events,
            int,
        ) or max_holder_events <= 0:
            raise ValueError(
                "max_holder_events must be a positive integer."
            )

        self.rpc_url = rpc_url.strip()

        self.factories = tuple(factories)

        # ------------------------------------------------------------------
        # Contract analysis
        # ------------------------------------------------------------------

        self.contract_analyzer = EVMContractAnalyzer(
            self.rpc_url,
            timeout=float(timeout),
        )

        # ------------------------------------------------------------------
        # Liquidity analysis
        # ------------------------------------------------------------------

        self.liquidity_analyzer = EVMLiquidityAnalyzer(
            self.rpc_url,
            timeout=float(timeout),
        )

        # ------------------------------------------------------------------
        # Holder analysis
        # ------------------------------------------------------------------

        self.holder_analyzer = EVMHolderAnalyzer(
            self.rpc_url,
            timeout=float(timeout),
            log_chunk_size=log_chunk_size,
        )

        # ------------------------------------------------------------------
        # Demand analysis
        # ------------------------------------------------------------------

        self.demand_analyzer = EVMDemandAnalyzer(
            self.rpc_url,
            timeout=float(timeout),
            log_chunk_size=log_chunk_size,
            max_events=max_holder_events,
        )

        # ------------------------------------------------------------------
        # Risk analysis
        # ------------------------------------------------------------------

        self.risk_analyzer = TokenRiskAnalyzer()

        # ------------------------------------------------------------------
        # DEX discovery
        # ------------------------------------------------------------------

        if dex_log_chunk_size is None:
            dex_log_chunk_size = DEFAULT_DEX_LOG_CHUNK_SIZE

        self.dex_discovery = EthereumDexDiscovery(
            self.rpc_url,
            factories=self.factories,
            timeout=float(timeout),
            log_chunk_size=dex_log_chunk_size,
            max_blocks=dex_max_blocks,
            max_pools=dex_max_pools,
        )

    # =========================================================================
    # Public API - single token
    # =========================================================================

    def scan(
        self,
        token_address: str,
        *,
        pool_addresses: Iterable[str],
        from_block: int,
        to_block: int | None = None,
        decimals: int | None = None,
        contract_verified: bool = False,
        complete_holder_history: bool = False,
    ) -> TokenScanResult:
        """
        Perform a complete read-only analysis of one EVM token.

        All values originate from the configured blockchain/RPC and
        analysis services. No market values are fabricated.
        """

        # ------------------------------------------------------------------
        # Contract analysis
        # ------------------------------------------------------------------

        try:
            contract = self.contract_analyzer.analyze(
                token_address,
                verified=contract_verified,
            )
        except Exception as exc:
            raise TokenScannerError(
                "Contract analysis failed for "
                f"{token_address!r}."
            ) from exc

        if not contract.is_contract:
            raise TokenScannerError(
                "The supplied address does not contain "
                "contract bytecode."
            )

        if not contract.is_erc20_like:
            raise TokenScannerError(
                "The supplied contract does not appear "
                "to be ERC-20 compatible."
            )

        if decimals is None:
            decimals = (
                contract.decimals
                if contract.decimals is not None
                else 18
            )

        # ------------------------------------------------------------------
        # Normalize pool addresses
        # ------------------------------------------------------------------

        normalized_pool_addresses = self._unique_addresses(
            pool_addresses,
        )

        # ------------------------------------------------------------------
        # Liquidity analysis
        # ------------------------------------------------------------------

        try:
            liquidity = self.liquidity_analyzer.analyze(
                contract.address,
                pool_addresses=normalized_pool_addresses,
            )
        except Exception as exc:
            raise TokenScannerError(
                "Liquidity analysis failed for "
                f"{contract.address}."
            ) from exc

        # ------------------------------------------------------------------
        # Holder analysis
        # ------------------------------------------------------------------

        try:
            holders = self.holder_analyzer.analyze(
                contract.address,
                from_block=from_block,
                to_block=to_block,
                decimals=decimals,
                complete_history=complete_holder_history,
            )
        except Exception as exc:
            raise TokenScannerError(
                "Holder analysis failed for "
                f"{contract.address}."
            ) from exc

        # ------------------------------------------------------------------
        # Demand analysis
        # ------------------------------------------------------------------

        try:
            demand = self.demand_analyzer.analyze(
                contract.address,
                pool_addresses=normalized_pool_addresses,
                from_block=from_block,
                to_block=to_block,
                decimals=decimals,
            )
        except Exception as exc:
            raise TokenScannerError(
                "Demand analysis failed for "
                f"{contract.address}."
            ) from exc

        # ------------------------------------------------------------------
        # Risk analysis
        # ------------------------------------------------------------------

        risk = self.risk_analyzer.analyze(
            contract_data=self._contract_risk_data(
                contract,
            ),
            liquidity_data=self._liquidity_risk_data(
                liquidity,
            ),
            holder_data=self._holder_risk_data(
                holders,
                from_block=from_block,
                to_block=to_block,
            ),
            demand_data=self._demand_risk_data(
                demand,
                from_block=from_block,
                to_block=to_block,
            ),
        )

        warnings = self._collect_warnings(
            contract=contract,
            liquidity=liquidity,
            holders=holders,
            demand=demand,
            risk=risk,
        )

        return TokenScanResult(
            token_address=contract.address,
            contract=contract,
            liquidity=liquidity,
            holders=holders,
            demand=demand,
            risk=risk,
            warnings=tuple(warnings),
        )

    # =========================================================================
    # Public API - real DEX discovery
    # =========================================================================

    def discover_pools(
        self,
        *,
        from_block: int,
        to_block: int | None = None,
    ) -> DexDiscoveryResult:
        """
        Discover real DEX pools from configured factory contracts.

        This is strictly read-only.

        The discovery service reads PairCreated-style events from the
        Ethereum RPC and returns real pool/token addresses.
        """

        if not self.factories:
            raise TokenDiscoveryScanError(
                "No DEX factories are configured. "
                "Configure at least one DexFactory before "
                "running real token discovery."
            )

        try:
            return self.dex_discovery.discover(
                from_block=from_block,
                to_block=to_block,
            )
        except DexDiscoveryConfigurationError as exc:
            raise TokenDiscoveryScanError(
                "DEX discovery configuration is invalid."
            ) from exc
        except Exception as exc:
            raise TokenDiscoveryScanError(
                "Ethereum DEX discovery failed."
            ) from exc

    def discover_and_scan(
        self,
        *,
        from_block: int,
        to_block: int | None = None,
        contract_verified: bool = False,
        complete_holder_history: bool = False,
        max_tokens: int | None = None,
    ) -> TokenDiscoveryScanResult:
        """
        Discover real DEX pools and analyze their real token contracts.

        Every token address originates from an observed DEX factory event.

        max_tokens limits how many unique discovered token contracts are
        analyzed. Discovery itself remains bounded by the DEX discovery
        configuration.
        """

        if max_tokens is not None:
            if (
                isinstance(max_tokens, bool)
                or not isinstance(max_tokens, int)
                or max_tokens < 1
            ):
                raise ValueError(
                    "max_tokens must be a positive integer or None."
                )

        try:
            discovery = self.discover_pools(
                from_block=from_block,
                to_block=to_block,
            )
        except DexDiscoveryConfigurationError as exc:
            raise TokenDiscoveryScanError(
                "DEX discovery configuration is invalid."
            ) from exc
        except Exception as exc:
            raise TokenDiscoveryScanError(
                "Ethereum DEX discovery failed."
            ) from exc

        warnings: list[str] = list(
            discovery.warnings,
        )

        # ------------------------------------------------------------------
        # Build token -> pools mapping from real discovery results.
        # ------------------------------------------------------------------

        token_pools: dict[str, set[str]] = {}

        for pool in discovery.pools:
            for token_address in pool.tokens:
                token_pools.setdefault(
                    token_address,
                    set(),
                ).add(
                    pool.pool_address,
                )

        discovered_token_count = len(token_pools)

        # Apply the analysis limit before performing expensive token analysis.
        if max_tokens is not None:
            token_items = list(
                token_pools.items()
            )[:max_tokens]
        else:
            token_items = list(
                token_pools.items()
            )

        if (
            max_tokens is not None
            and discovered_token_count > max_tokens
        ):
            warnings.append(
                f"Token analysis limited to {max_tokens} of "
                f"{discovered_token_count} discovered tokens."
            )

        # ------------------------------------------------------------------
        # Analyze each selected real token once.
        # ------------------------------------------------------------------

        analyzed_tokens: list[DiscoveredTokenScan] = []

        for token_address, pools in token_items:
            pool_addresses = tuple(
                sorted(
                    pools,
                )
            )

            try:
                token_scan = self.scan(
                    token_address,
                    pool_addresses=pool_addresses,
                    from_block=from_block,
                    to_block=to_block,
                    contract_verified=contract_verified,
                    complete_holder_history=complete_holder_history,
                )

            except TokenScannerError as exc:
                warnings.append(
                    "Token analysis failed for "
                    f"{token_address}: {exc}"
                )
                continue

            except Exception as exc:
                warnings.append(
                    "Unexpected token analysis failure for "
                    f"{token_address}: {exc}"
                )
                continue

            analyzed_tokens.append(
                DiscoveredTokenScan(
                    token_address=token_scan.token_address,
                    pool_addresses=pool_addresses,
                    scan=token_scan,
                )
            )

            warnings.extend(
                token_scan.warnings,
            )

        return TokenDiscoveryScanResult(
            discovery=discovery,
            tokens=tuple(
                analyzed_tokens,
            ),
            warnings=tuple(
                self._unique_warnings(
                    warnings,
                ),
            ),
        )

    # =========================================================================
    # Discovery helpers
    # =========================================================================

    @staticmethod
    def _unique_addresses(
        addresses: Iterable[str],
    ) -> tuple[str, ...]:
        """
        Deduplicate pool addresses while preserving their first
        occurrence.

        The discovery layer already normalizes addresses, so this
        method intentionally does not invent or reinterpret addresses.
        """

        result: list[str] = []
        seen: set[str] = set()

        for address in addresses:
            if not isinstance(
                address,
                str,
            ):
                continue

            normalized = address.strip()

            if not normalized:
                continue

            key = normalized.lower()

            if key in seen:
                continue

            seen.add(key)
            result.append(normalized)

        return tuple(result)

    @staticmethod
    def _unique_warnings(
        warnings: Iterable[str],
    ) -> list[str]:
        """
        Remove duplicate warnings while preserving order.
        """

        result: list[str] = []

        for warning in warnings:
            if not warning:
                continue

            if warning not in result:
                result.append(warning)

        return result

    # =========================================================================
    # Risk adapters
    # =========================================================================

    @staticmethod
    def _contract_risk_data(
        analysis: ContractAnalysis,
    ) -> dict[str, Any]:
        return {
            "contract_verified": analysis.verified,
            "unlimited_mint_detected": (
                analysis.unlimited_mint_detected
            ),
            "blacklist_detected": (
                analysis.blacklist_function_detected
            ),
        }

    @staticmethod
    def _liquidity_risk_data(
        analysis: LiquidityAnalysis,
    ) -> dict[str, Any]:
        return {
            "total_liquidity_usd": (
                analysis.total_liquidity_usd
            ),
            "liquidity_pool_count": (
                analysis.liquidity_pool_count
            ),
            "liquidity_concentration_percentage": (
                analysis.liquidity_concentration_percentage
            ),
            "has_liquidity": (
                analysis.has_liquidity
            ),

            # The liquidity analyzer does not currently establish
            # a genuine lock provider. Therefore this MUST remain
            # False until a dedicated lock-verification layer exists.
            "liquidity_locked": False,
        }

    @staticmethod
    def _holder_risk_data(
        analysis: HolderAnalysis,
        *,
        from_block: int,
        to_block: int | None,
    ) -> dict[str, Any]:
        observation_blocks = (
            None
            if to_block is None
            else max(0, to_block - from_block + 1)
        )

        return {
            "holder_count": (
                analysis.holder_count
            ),
            "top_10_holder_percentage": (
                analysis.top_10_holder_percentage
            ),
            "complete_history": (
                analysis.complete_history
            ),
            "from_block": from_block,
            "to_block": to_block,
            "observation_block_count": observation_blocks,
        }

    @staticmethod
    def _demand_risk_data(
        analysis: DemandAnalysis,
        *,
        from_block: int,
        to_block: int | None,
    ) -> dict[str, Any]:
        observation_blocks = (
            None
            if to_block is None
            else max(0, to_block - from_block + 1)
        )

        return {
            "buy_count": analysis.buy_count,
            "sell_count": analysis.sell_count,
            "unique_buyers": analysis.unique_buyers,
            "unique_sellers": analysis.unique_sellers,
            "demand_pressure": analysis.demand_pressure,
            "buy_volume": analysis.buy_volume,
            "sell_volume": analysis.sell_volume,
            "from_block": from_block,
            "to_block": to_block,
            "observation_block_count": observation_blocks,
        }

    # =========================================================================
    # Warning aggregation
    # =========================================================================

    @staticmethod
    def _collect_warnings(
        *,
        contract: ContractAnalysis,
        liquidity: LiquidityAnalysis,
        holders: HolderAnalysis,
        demand: DemandAnalysis,
        risk: RiskAnalysis,
    ) -> list[str]:
        """
        Collect warnings from every analysis layer.

        Duplicates are removed while preserving order.
        """

        warnings: list[str] = []

        for source in (
            contract.warnings,
            liquidity.warnings,
            holders.warnings,
            demand.warnings,
            risk.warnings,
        ):
            for warning in source:
                if warning not in warnings:
                    warnings.append(warning)

        return warnings
