"""
HappyWallet Token Scanner - Scanner Orchestrator.

Coordinates the read-only token analysis services:

    Contract
        ↓
    Liquidity
        ↓
    Holders
        ↓
    Demand
        ↓
    Risk

Security rules:
    - Never request private keys.
    - Never request seed phrases.
    - Never sign transactions.
    - Never submit transactions.
    - Never approve token spending.
    - Never execute swaps.
    - Never automatically buy or sell tokens.

This module only orchestrates public blockchain analysis.
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


# ============================================================================
# Result
# ============================================================================


@dataclass(frozen=True)
class TokenScanResult:
    """
    Complete read-only analysis of an EVM token.
    """

    token_address: str

    contract: ContractAnalysis

    liquidity: LiquidityAnalysis

    holders: HolderAnalysis

    demand: DemandAnalysis

    risk: RiskAnalysis

    warnings: tuple[str, ...] = field(
        default_factory=tuple
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


# ============================================================================
# Exceptions
# ============================================================================


class TokenScannerError(Exception):
    """Base exception for token scanner orchestration."""


# ============================================================================
# Scanner
# ============================================================================


class EVMTokenScanner:
    """
    High-level read-only EVM token scanner.

    The scanner coordinates the individual analysis services but does not
    perform any transaction execution.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        timeout: float = 10.0,
        log_chunk_size: int = 2_000,
        max_holder_events: int = 50_000,
    ) -> None:
        if not isinstance(
            rpc_url,
            str,
        ) or not rpc_url.strip():
            raise ValueError(
                "rpc_url must be a non-empty string."
            )

        self.rpc_url = rpc_url.strip()

        self.contract_analyzer = (
            EVMContractAnalyzer(
                self.rpc_url,
                timeout=timeout,
            )
        )

        self.liquidity_analyzer = (
            EVMLiquidityAnalyzer(
                self.rpc_url,
                timeout=timeout,
            )
        )

        self.holder_analyzer = (
            EVMHolderAnalyzer(
                self.rpc_url,
                timeout=timeout,
                log_chunk_size=log_chunk_size,
            )
        )

        self.demand_analyzer = (
            EVMDemandAnalyzer(
                self.rpc_url,
                timeout=timeout,
                log_chunk_size=log_chunk_size,
                max_events=max_holder_events,
            )
        )

        self.risk_analyzer = TokenRiskAnalyzer()

    # =========================================================================
    # Public API
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
        Perform a complete read-only token scan.

        Parameters
        ----------
        token_address:
            ERC-20 token contract address.

        pool_addresses:
            Known liquidity-pool addresses.

        from_block:
            First block to scan for holder and demand analysis.

        to_block:
            Last block to scan. Defaults to latest block.

        decimals:
            Optional token decimal override.

            When omitted, the scanner uses the value discovered by
            contract analysis when available, otherwise 18.

        contract_verified:
            Whether source verification has been established externally.

        complete_holder_history:
            Whether the supplied holder event range represents complete
            token history.
        """

        # ------------------------------------------------------------------
        # Contract analysis
        # ------------------------------------------------------------------

        contract = self.contract_analyzer.analyze(
            token_address,
            verified=contract_verified,
        )

        if not contract.is_contract:
            raise TokenScannerError(
                "The supplied address does not contain contract bytecode."
            )

        if decimals is None:
            decimals = (
                contract.decimals
                if contract.decimals is not None
                else 18
            )

        # ------------------------------------------------------------------
        # Liquidity analysis
        # ------------------------------------------------------------------

        liquidity = self.liquidity_analyzer.analyze(
            contract.address,
            pool_addresses=pool_addresses,
        )

        # ------------------------------------------------------------------
        # Holder analysis
        # ------------------------------------------------------------------

        holders = self.holder_analyzer.analyze(
            contract.address,
            from_block=from_block,
            to_block=to_block,
            decimals=decimals,
            complete_history=complete_holder_history,
        )

        # ------------------------------------------------------------------
        # Demand analysis
        # ------------------------------------------------------------------

        demand = self.demand_analyzer.analyze(
            contract.address,
            pool_addresses=pool_addresses,
            from_block=from_block,
            to_block=to_block,
            decimals=decimals,
        )

        # ------------------------------------------------------------------
        # Risk analysis
        # ------------------------------------------------------------------

        risk = self.risk_analyzer.analyze(
            contract_data=self._contract_risk_data(
                contract
            ),
            liquidity_data=self._liquidity_risk_data(
                liquidity
            ),
            holder_data=self._holder_risk_data(
                holders
            ),
            demand_data=self._demand_risk_data(
                demand
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

            # The current liquidity analyzer does not yet establish
            # a genuine lock provider. Therefore this remains False
            # until a dedicated liquidity-lock verification layer exists.
            "liquidity_locked": False,
        }

    @staticmethod
    def _holder_risk_data(
        analysis: HolderAnalysis,
    ) -> dict[str, Any]:
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
        }

    @staticmethod
    def _demand_risk_data(
        analysis: DemandAnalysis,
    ) -> dict[str, Any]:
        return {
            "buy_count": analysis.buy_count,
            "sell_count": analysis.sell_count,
            "unique_buyers": analysis.unique_buyers,
            "unique_sellers": analysis.unique_sellers,
            "demand_pressure": analysis.demand_pressure,
            "buy_volume": analysis.buy_volume,
            "sell_volume": analysis.sell_volume,
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
        Collect warnings from all analysis layers.

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
