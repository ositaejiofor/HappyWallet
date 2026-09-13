"""
HappyWallet Token Scanner - Risk Analysis.

Combines public token, liquidity, holder and demand information
into an explainable 0-100 risk score.

IMPORTANT:
    This is an analytical risk model.

    It is NOT:
        - financial advice
        - a guarantee of profit
        - a prediction of future price
        - a guarantee that a token is safe

Security:
    - No private keys.
    - No seed phrases.
    - No signing.
    - No transaction execution.
    - No token approvals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any


# ============================================================================
# Constants
# ============================================================================

MIN_SCORE = 0
MAX_SCORE = 100

# A high score means lower observed risk.
#
# The score starts at 100 and risk deductions are applied.
STARTING_SCORE = Decimal("100")

# Maximum deductions by category.
MAX_CONTRACT_DEDUCTION = Decimal("30")
MAX_LIQUIDITY_DEDUCTION = Decimal("25")
MAX_HOLDER_DEDUCTION = Decimal("25")
MAX_DEMAND_DEDUCTION = Decimal("20")


# ============================================================================
# Result objects
# ============================================================================


@dataclass(frozen=True)
class RiskFinding:
    """
    One explainable risk finding.
    """

    category: str

    severity: str

    points: Decimal

    title: str

    explanation: str


@dataclass(frozen=True)
class RiskAnalysis:
    """
    Complete risk assessment.
    """

    score: int

    rating: str

    contract_risk_points: Decimal

    liquidity_risk_points: Decimal

    holder_risk_points: Decimal

    demand_risk_points: Decimal

    findings: tuple[RiskFinding, ...] = field(
        default_factory=tuple
    )

    warnings: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def is_high_risk(self) -> bool:
        return self.score < 40

    @property
    def is_medium_risk(self) -> bool:
        return 40 <= self.score < 70

    @property
    def is_lower_observed_risk(self) -> bool:
        return self.score >= 70


# ============================================================================
# Analyzer
# ============================================================================


class TokenRiskAnalyzer:
    """
    Explainable risk scoring engine.

    The engine accepts plain dictionaries so it remains loosely coupled
    to the other scanner services.

    Expected data:

        contract_data
        liquidity_data
        holder_data
        demand_data

    Each dictionary may contain only the fields available from the
    corresponding scanner.
    """

    def analyze(
        self,
        *,
        contract_data: dict[str, Any] | None = None,
        liquidity_data: dict[str, Any] | None = None,
        holder_data: dict[str, Any] | None = None,
        demand_data: dict[str, Any] | None = None,
    ) -> RiskAnalysis:
        """
        Calculate the overall risk score.
        """

        contract_data = contract_data or {}
        liquidity_data = liquidity_data or {}
        holder_data = holder_data or {}
        demand_data = demand_data or {}

        findings: list[RiskFinding] = []

        contract_points, contract_findings = (
            self._score_contract(
                contract_data
            )
        )

        liquidity_points, liquidity_findings = (
            self._score_liquidity(
                liquidity_data
            )
        )

        holder_points, holder_findings = (
            self._score_holders(
                holder_data
            )
        )

        demand_points, demand_findings = (
            self._score_demand(
                demand_data
            )
        )

        findings.extend(contract_findings)
        findings.extend(liquidity_findings)
        findings.extend(holder_findings)
        findings.extend(demand_findings)

        total_deduction = (
            contract_points
            + liquidity_points
            + holder_points
            + demand_points
        )

        raw_score = (
            STARTING_SCORE
            - total_deduction
        )

        score = self._clamp_score(
            raw_score
        )

        rating = self._rating_for_score(
            score
        )

        warnings = self._build_warnings(
            score=score,
            findings=findings,
            contract_data=contract_data,
            liquidity_data=liquidity_data,
            holder_data=holder_data,
            demand_data=demand_data,
        )

        return RiskAnalysis(
            score=score,
            rating=rating,
            contract_risk_points=contract_points,
            liquidity_risk_points=liquidity_points,
            holder_risk_points=holder_points,
            demand_risk_points=demand_points,
            findings=tuple(findings),
            warnings=tuple(warnings),
        )

    # =========================================================================
    # Contract scoring
    # =========================================================================

    def _score_contract(
        self,
        data: dict[str, Any],
    ) -> tuple[
        Decimal,
        list[RiskFinding],
    ]:
        """
        Score contract-level risks.

        Maximum deduction: 30 points.
        """

        points = Decimal("0")
        findings: list[RiskFinding] = []

        verified = bool(
            data.get(
                "contract_verified",
                False,
            )
        )

        unlimited_mint = bool(
            data.get(
                "unlimited_mint_detected",
                False,
            )
        )

        blacklist = bool(
            data.get(
                "blacklist_detected",
                False,
            )
        )

        if not verified:
            deduction = Decimal("8")

            points += deduction

            findings.append(
                RiskFinding(
                    category="contract",
                    severity="medium",
                    points=deduction,
                    title="Contract is not verified",
                    explanation=(
                        "The scanner could not confirm that the "
                        "contract source code is verified."
                    ),
                )
            )

        if unlimited_mint:
            deduction = Decimal("15")

            points += deduction

            findings.append(
                RiskFinding(
                    category="contract",
                    severity="critical",
                    points=deduction,
                    title="Unlimited mint capability detected",
                    explanation=(
                        "The contract appears to retain a capability "
                        "that may allow additional token supply to be "
                        "created."
                    ),
                )
            )

        if blacklist:
            deduction = Decimal("15")

            points += deduction

            findings.append(
                RiskFinding(
                    category="contract",
                    severity="critical",
                    points=deduction,
                    title="Blacklist mechanism detected",
                    explanation=(
                        "The contract appears to contain logic that "
                        "may restrict transfers for selected addresses."
                    ),
                )
            )

        return (
            min(
                points,
                MAX_CONTRACT_DEDUCTION,
            ),
            findings,
        )

    # =========================================================================
    # Liquidity scoring
    # =========================================================================

    def _score_liquidity(
        self,
        data: dict[str, Any],
    ) -> tuple[
        Decimal,
        list[RiskFinding],
    ]:
        """
        Score liquidity risks.

        Maximum deduction: 25 points.
        """

        points = Decimal("0")
        findings: list[RiskFinding] = []

        liquidity = self._decimal(
            data.get(
                "total_liquidity_usd"
            )
        )

        pool_count = self._integer(
            data.get(
                "liquidity_pool_count",
                0,
            )
        )

        concentration = self._decimal(
            data.get(
                "liquidity_concentration_percentage"
            )
        )

        liquidity_locked = bool(
            data.get(
                "liquidity_locked",
                False,
            )
        )

        has_liquidity = bool(
            data.get(
                "has_liquidity",
                False,
            )
        )

        if not has_liquidity:
            deduction = Decimal("20")

            points += deduction

            findings.append(
                RiskFinding(
                    category="liquidity",
                    severity="critical",
                    points=deduction,
                    title="No known liquidity",
                    explanation=(
                        "The scanner could not identify usable "
                        "liquidity for the token."
                    ),
                )
            )

        elif liquidity is not None:

            if liquidity < Decimal("10_000"):
                deduction = Decimal("20")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="liquidity",
                        severity="critical",
                        points=deduction,
                        title="Extremely thin liquidity",
                        explanation=(
                            "Known liquidity is below $10,000. "
                            "Large trades may have extreme slippage."
                        ),
                    )
                )

            elif liquidity < Decimal("25_000"):
                deduction = Decimal("15")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="liquidity",
                        severity="high",
                        points=deduction,
                        title="Very low liquidity",
                        explanation=(
                            "Known liquidity is below $25,000."
                        ),
                    )
                )

            elif liquidity < Decimal("100_000"):
                deduction = Decimal("8")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="liquidity",
                        severity="medium",
                        points=deduction,
                        title="Moderate liquidity",
                        explanation=(
                            "Known liquidity is below $100,000."
                        ),
                    )
                )

        if pool_count == 1:
            deduction = Decimal("3")

            points += deduction

            findings.append(
                RiskFinding(
                    category="liquidity",
                    severity="low",
                    points=deduction,
                    title="Single known liquidity pool",
                    explanation=(
                        "The token currently has only one known "
                        "liquidity pool."
                    ),
                )
            )

        if (
            concentration is not None
            and concentration >= Decimal("90")
            and pool_count > 1
        ):
            deduction = Decimal("4")

            points += deduction

            findings.append(
                RiskFinding(
                    category="liquidity",
                    severity="medium",
                    points=deduction,
                    title="Liquidity is highly concentrated",
                    explanation=(
                        "More than 90% of known liquidity is "
                        "concentrated in one pool."
                    ),
                )
            )

        # A liquidity-lock finding only makes sense when liquidity
        # actually exists. When there is no known liquidity, the
        # "No known liquidity" finding already represents that risk.
        if has_liquidity and not liquidity_locked:
            deduction = Decimal("5")

            points += deduction

            findings.append(
                RiskFinding(
                    category="liquidity",
                    severity="medium",
                    points=deduction,
                    title="Liquidity lock not confirmed",
                    explanation=(
                        "The scanner could not verify that liquidity "
                        "is locked."
                    ),
                )
            )

        return (
            min(
                points,
                MAX_LIQUIDITY_DEDUCTION,
            ),
            findings,
        )

    # =========================================================================
    # Holder scoring
    # =========================================================================

    def _score_holders(
        self,
        data: dict[str, Any],
    ) -> tuple[
        Decimal,
        list[RiskFinding],
    ]:
        """
        Score holder concentration.

        Maximum deduction: 25 points.

        Bounded scans are treated as limited evidence. A short event
        window cannot reliably establish the token's complete holder
        distribution, so observed holder counts and concentration are
        not treated as critical risks unless the observation is
        sufficiently comprehensive.
        """

        points = Decimal("0")
        findings: list[RiskFinding] = []

        holder_count = self._integer(
            data.get(
                "holder_count"
            )
        )

        top_10 = self._decimal(
            data.get(
                "top_10_holder_percentage"
            )
        )

        complete_history = bool(
            data.get(
                "complete_history",
                False,
            )
        )

        observation_blocks = self._integer(
            data.get(
                "observation_block_count"
            )
        )

        limited_observation = (
            not complete_history
            and observation_blocks is not None
            and observation_blocks < 1000
        )

        if holder_count is not None:

            if limited_observation:

                if holder_count < 10:
                    deduction = Decimal("2")

                    points += deduction

                    findings.append(
                        RiskFinding(
                            category="holders",
                            severity="low",
                            points=deduction,
                            title="Limited holder observation",
                            explanation=(
                                "Fewer than 10 positive-balance holders "
                                "were reconstructed, but the observation "
                                f"covered only {observation_blocks} blocks. "
                                "This is insufficient evidence to establish "
                                "the token's complete holder distribution."
                            ),
                        )
                    )

            elif holder_count < 10:
                deduction = Decimal("15")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="holders",
                        severity="critical",
                        points=deduction,
                        title="Extremely small holder base",
                        explanation=(
                            "Fewer than 10 positive-balance holders "
                            "were observed."
                        ),
                    )
                )

            elif holder_count < 50:
                deduction = Decimal("10")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="holders",
                        severity="high",
                        points=deduction,
                        title="Small holder base",
                        explanation=(
                            "Fewer than 50 positive-balance holders "
                            "were observed."
                        ),
                    )
                )

            elif holder_count < 200:
                deduction = Decimal("5")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="holders",
                        severity="medium",
                        points=deduction,
                        title="Limited holder distribution",
                        explanation=(
                            "Fewer than 200 positive-balance holders "
                            "were observed."
                        ),
                    )
                )

        if top_10 is not None:

            if limited_observation:

                if top_10 >= Decimal("90"):
                    deduction = Decimal("3")

                    points += deduction

                    findings.append(
                        RiskFinding(
                            category="holders",
                            severity="low",
                            points=deduction,
                            title="High observed holder concentration",
                            explanation=(
                                "The top 10 reconstructed holders control "
                                "at least 90% of the observed balance, but "
                                f"the measurement covers only "
                                f"{observation_blocks} blocks. The result "
                                "should not be treated as a complete "
                                "supply-distribution measurement."
                            ),
                        )
                    )

                elif top_10 >= Decimal("75"):
                    deduction = Decimal("2")

                    points += deduction

                    findings.append(
                        RiskFinding(
                            category="holders",
                            severity="low",
                            points=deduction,
                            title="Elevated observed holder concentration",
                            explanation=(
                                "The top 10 reconstructed holders control "
                                "at least 75% of the observed balance, but "
                                f"the measurement covers only "
                                f"{observation_blocks} blocks."
                            ),
                        )
                    )

            elif top_10 >= Decimal("90"):
                deduction = Decimal("15")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="holders",
                        severity="critical",
                        points=deduction,
                        title="Extreme holder concentration",
                        explanation=(
                            "The top 10 observed holders control "
                            "at least 90% of the measured supply."
                        ),
                    )
                )

            elif top_10 >= Decimal("75"):
                deduction = Decimal("10")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="holders",
                        severity="high",
                        points=deduction,
                        title="Very high holder concentration",
                        explanation=(
                            "The top 10 observed holders control "
                            "at least 75% of the measured supply."
                        ),
                    )
                )

            elif top_10 >= Decimal("50"):
                deduction = Decimal("6")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="holders",
                        severity="medium",
                        points=deduction,
                        title="High holder concentration",
                        explanation=(
                            "The top 10 observed holders control "
                            "at least 50% of the measured supply."
                        ),
                    )
                )

        if not complete_history and not limited_observation:
            deduction = Decimal("3")

            points += deduction

            findings.append(
                RiskFinding(
                    category="holders",
                    severity="medium",
                    points=deduction,
                    title="Holder scan is incomplete",
                    explanation=(
                        "The holder distribution was reconstructed "
                        "from a bounded event scan."
                    ),
                )
            )

        return (
            min(
                points,
                MAX_HOLDER_DEDUCTION,
            ),
            findings,
        )

    # =========================================================================
    # Demand scoring
    # =========================================================================

    def _score_demand(
        self,
        data: dict[str, Any],
    ) -> tuple[
        Decimal,
        list[RiskFinding],
    ]:
        """
        Score observed market-demand risks.

        Maximum deduction: 20 points.

        Short bounded scans are treated as limited market evidence.
        Absence of observed buys or sells during a short window must
        not be interpreted as proof that the token has no demand.
        """

        points = Decimal("0")
        findings: list[RiskFinding] = []

        buy_count = self._integer(
            data.get(
                "buy_count",
                0,
            )
        ) or 0

        sell_count = self._integer(
            data.get(
                "sell_count",
                0,
            )
        ) or 0

        unique_buyers = self._integer(
            data.get(
                "unique_buyers",
                0,
            )
        ) or 0

        unique_sellers = self._integer(
            data.get(
                "unique_sellers",
                0,
            )
        ) or 0

        pressure = self._decimal(
            data.get(
                "demand_pressure"
            )
        )

        buy_volume = self._decimal(
            data.get(
                "buy_volume"
            )
        )

        sell_volume = self._decimal(
            data.get(
                "sell_volume"
            )
        )

        observation_blocks = self._integer(
            data.get(
                "observation_block_count"
            )
        )

        limited_observation = (
            observation_blocks is not None
            and observation_blocks < 1000
        )

        if limited_observation:

            if (
                buy_count == 0
                and sell_count == 0
            ):
                deduction = Decimal("1")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="demand",
                        severity="low",
                        points=deduction,
                        title="Limited market observation",
                        explanation=(
                            "No pool-directed buys or sells were observed "
                            f"during the {observation_blocks}-block scan. "
                            "This is insufficient evidence to determine "
                            "the token's overall market demand."
                        ),
                    )
                )

            elif buy_count == 0:
                deduction = Decimal("2")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="demand",
                        severity="low",
                        points=deduction,
                        title="No observed buys in limited window",
                        explanation=(
                            "The scan observed sells but no classified "
                            f"pool-directed buys during the "
                            f"{observation_blocks}-block observation "
                            "window. A longer observation period is "
                            "required before treating this as a strong "
                            "demand-risk signal."
                        ),
                    )
                )

        else:

            if (
                buy_count == 0
                and sell_count == 0
            ):
                deduction = Decimal("12")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="demand",
                        severity="high",
                        points=deduction,
                        title="No observed market activity",
                        explanation=(
                            "No pool-directed buys or sells were observed "
                            "during the scan."
                        ),
                    )
                )

            elif buy_count == 0:
                deduction = Decimal("10")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="demand",
                        severity="high",
                        points=deduction,
                        title="No observed buys",
                        explanation=(
                            "The scan observed sells but no classified "
                            "pool-directed buys."
                        ),
                    )
                )

            elif unique_buyers < 5:
                deduction = Decimal("8")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="demand",
                        severity="high",
                        points=deduction,
                        title="Very few unique buyers",
                        explanation=(
                            "Observed buying activity comes from fewer "
                            "than five unique buyer addresses."
                        ),
                    )
                )

            elif unique_buyers < 20:
                deduction = Decimal("4")

                points += deduction

                findings.append(
                    RiskFinding(
                        category="demand",
                        severity="medium",
                        points=deduction,
                        title="Limited buyer participation",
                        explanation=(
                            "Fewer than 20 unique buyers were observed."
                        ),
                    )
                )

        if (
            not limited_observation
            and pressure is not None
            and pressure <= Decimal("-50")
        ):
            deduction = Decimal("8")

            points += deduction

            findings.append(
                RiskFinding(
                    category="demand",
                    severity="high",
                    points=deduction,
                    title="Strong observed sell pressure",
                    explanation=(
                        "Observed sell volume substantially exceeds "
                        "buy volume."
                    ),
                )
            )

        elif (
            not limited_observation
            and pressure is not None
            and pressure < Decimal("0")
        ):
            deduction = Decimal("4")

            points += deduction

            findings.append(
                RiskFinding(
                    category="demand",
                    severity="medium",
                    points=deduction,
                    title="Observed sell pressure",
                    explanation=(
                        "Observed sell volume exceeds buy volume."
                    ),
                )
            )

        if (
            not limited_observation
            and buy_volume is not None
            and sell_volume is not None
            and buy_volume > 0
            and sell_volume > 0
            and sell_volume > buy_volume * Decimal("3")
        ):
            deduction = Decimal("5")

            points += deduction

            findings.append(
                RiskFinding(
                    category="demand",
                    severity="high",
                    points=deduction,
                    title="Sell volume dominates",
                    explanation=(
                        "Observed sell volume is more than three "
                        "times observed buy volume."
                    ),
                )
            )

        if (
            not limited_observation
            and unique_sellers > 0
            and unique_buyers > 0
            and unique_sellers > unique_buyers * 3
        ):
            deduction = Decimal("3")

            points += deduction

            findings.append(
                RiskFinding(
                    category="demand",
                    severity="medium",
                    points=deduction,
                    title="Seller participation dominates",
                    explanation=(
                        "There are substantially more observed "
                        "sellers than buyers."
                    ),
                )
            )

        return (
            min(
                points,
                MAX_DEMAND_DEDUCTION,
            ),
            findings,
        )

    # =========================================================================
    # Warnings
    # =========================================================================

    def _build_warnings(
        self,
        *,
        score: int,
        findings: list[RiskFinding],
        contract_data: dict[str, Any],
        liquidity_data: dict[str, Any],
        holder_data: dict[str, Any],
        demand_data: dict[str, Any],
    ) -> list[str]:
        warnings: list[str] = []

        critical_findings = [
            finding
            for finding in findings
            if finding.severity == "critical"
        ]

        if critical_findings:
            warnings.append(
                "One or more critical contract, liquidity or "
                "distribution risks were detected."
            )

        if score < 40:
            warnings.append(
                "This token has a high observed risk score."
            )

        elif score < 70:
            warnings.append(
                "This token has a medium observed risk score."
            )

        else:
            warnings.append(
                "The scanner found fewer major risks, but this "
                "does not establish that the token is safe."
            )

        if not contract_data:
            warnings.append(
                "Contract analysis data was not supplied."
            )

        if not liquidity_data:
            warnings.append(
                "Liquidity analysis data was not supplied."
            )

        if not holder_data:
            warnings.append(
                "Holder analysis data was not supplied."
            )

        if not demand_data:
            warnings.append(
                "Demand analysis data was not supplied."
            )

        return warnings

    # =========================================================================
    # Helpers
    # =========================================================================

    @staticmethod
    def _decimal(
        value: Any,
    ) -> Decimal | None:
        if value is None:
            return None

        if isinstance(value, Decimal):
            return value

        try:
            return Decimal(
                str(value)
            )
        except (
            ValueError,
            TypeError,
        ):
            return None

    @staticmethod
    def _integer(
        value: Any,
    ) -> int | None:
        if value is None:
            return None

        try:
            return int(value)
        except (
            ValueError,
            TypeError,
        ):
            return None

    @staticmethod
    def _clamp_score(
        score: Decimal,
    ) -> int:
        score = max(
            Decimal(MIN_SCORE),
            min(
                Decimal(MAX_SCORE),
                score,
            ),
        )

        return int(
            score.quantize(
                Decimal("1")
            )
        )

    @staticmethod
    def _rating_for_score(
        score: int,
    ) -> str:
        if score >= 80:
            return "LOWER_OBSERVED_RISK"

        if score >= 60:
            return "MODERATE_OBSERVED_RISK"

        if score >= 40:
            return "HIGH_OBSERVED_RISK"

        return "VERY_HIGH_OBSERVED_RISK"