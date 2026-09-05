from decimal import Decimal

from django.test import SimpleTestCase

from apps.token_scanner.services.risk import TokenRiskAnalyzer


class TokenRiskAnalyzerTests(SimpleTestCase):
    """
    Tests for the explainable token risk scoring engine.

    These tests verify:
        - score calculation
        - individual risk categories
        - critical findings
        - score boundaries
        - warning generation
        - missing-data handling
    """

    def setUp(self):
        self.analyzer = TokenRiskAnalyzer()

    # ========================================================================
    # Basic scoring
    # ========================================================================

    def test_safe_observed_profile_gets_high_score(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": True,
                "unlimited_mint_detected": False,
                "blacklist_detected": False,
            },
            liquidity_data={
                "total_liquidity_usd": Decimal("500000"),
                "liquidity_pool_count": 3,
                "liquidity_concentration_percentage": Decimal("40"),
                "has_liquidity": True,
                "liquidity_locked": True,
            },
            holder_data={
                "holder_count": 1000,
                "top_10_holder_percentage": Decimal("20"),
                "complete_history": True,
            },
            demand_data={
                "buy_count": 100,
                "sell_count": 50,
                "unique_buyers": 50,
                "unique_sellers": 30,
                "buy_volume": Decimal("100000"),
                "sell_volume": Decimal("40000"),
                "demand_pressure": Decimal("42.86"),
            },
        )

        self.assertEqual(result.score, 100)
        self.assertEqual(
            result.rating,
            "LOWER_OBSERVED_RISK",
        )

    def test_empty_data_produces_high_observed_risk(self):
        result = self.analyzer.analyze()

        self.assertEqual(
            result.rating,
            "HIGH_OBSERVED_RISK",
        )

        self.assertEqual(
            result.contract_risk_points,
            Decimal("8"),
        )

        self.assertEqual(
            result.liquidity_risk_points,
            Decimal("20"),
        )

        self.assertEqual(
            result.holder_risk_points,
            Decimal("3"),
        )

        self.assertEqual(
            result.demand_risk_points,
            Decimal("12"),
        )

        expected_score = (
            100
            - 8
            - 20
            - 3
            - 12
        )

        self.assertEqual(
            result.score,
            expected_score,
        )

        self.assertTrue(
            any(
                finding.title == "Contract is not verified"
                for finding in result.findings
            )
        )

        self.assertTrue(
            any(
                finding.title == "No known liquidity"
                for finding in result.findings
            )
        )

        self.assertTrue(
            any(
                finding.title == "No observed market activity"
                for finding in result.findings
            )
        )

    # ========================================================================
    # Contract risks
    # ========================================================================

    def test_unverified_contract_deducts_eight_points(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": False,
            },
        )

        self.assertEqual(
            result.contract_risk_points,
            Decimal("8"),
        )

        self.assertTrue(
            any(
                finding.title == "Contract is not verified"
                for finding in result.findings
            )
        )

    def test_verified_contract_has_no_verification_deduction(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": True,
            },
        )

        self.assertEqual(
            result.contract_risk_points,
            Decimal("0"),
        )

    def test_unlimited_mint_is_critical(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": True,
                "unlimited_mint_detected": True,
            },
        )

        self.assertEqual(
            result.contract_risk_points,
            Decimal("15"),
        )

        finding = next(
            finding
            for finding in result.findings
            if finding.title == "Unlimited mint capability detected"
        )

        self.assertEqual(
            finding.severity,
            "critical",
        )

    def test_blacklist_detection_is_critical(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": True,
                "blacklist_detected": True,
            },
        )

        self.assertEqual(
            result.contract_risk_points,
            Decimal("15"),
        )

        finding = next(
            finding
            for finding in result.findings
            if finding.title == "Blacklist mechanism detected"
        )

        self.assertEqual(
            finding.severity,
            "critical",
        )

    def test_contract_deduction_is_capped(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": False,
                "unlimited_mint_detected": True,
                "blacklist_detected": True,
            },
        )

        self.assertEqual(
            result.contract_risk_points,
            Decimal("30"),
        )

    # ========================================================================
    # Liquidity risks
    # ========================================================================

    def test_no_liquidity_is_critical(self):
        result = self.analyzer.analyze(
            liquidity_data={
                "has_liquidity": False,
            },
        )

        self.assertEqual(
            result.liquidity_risk_points,
            Decimal("20"),
        )

        self.assertTrue(
            any(
                finding.title == "No known liquidity"
                for finding in result.findings
            )
        )

    def test_extremely_thin_liquidity_deducts_twenty(self):
        result = self.analyzer.analyze(
            liquidity_data={
                "has_liquidity": True,
                "total_liquidity_usd": Decimal("5000"),
            },
        )

        self.assertEqual(
            result.liquidity_risk_points,
            Decimal("25"),
        )

    def test_single_pool_adds_liquidity_risk(self):
        result = self.analyzer.analyze(
            liquidity_data={
                "has_liquidity": True,
                "total_liquidity_usd": Decimal("500000"),
                "liquidity_pool_count": 1,
                "liquidity_locked": True,
            },
        )

        self.assertEqual(
            result.liquidity_risk_points,
            Decimal("3"),
        )

    def test_unlocked_liquidity_adds_risk(self):
        result = self.analyzer.analyze(
            liquidity_data={
                "has_liquidity": True,
                "total_liquidity_usd": Decimal("500000"),
                "liquidity_pool_count": 3,
                "liquidity_locked": False,
            },
        )

        self.assertEqual(
            result.liquidity_risk_points,
            Decimal("5"),
        )

    def test_liquidity_deduction_is_capped(self):
        result = self.analyzer.analyze(
            liquidity_data={
                "has_liquidity": False,
                "liquidity_pool_count": 1,
                "liquidity_locked": False,
            },
        )

        self.assertLessEqual(
            result.liquidity_risk_points,
            Decimal("25"),
        )

    # ========================================================================
    # Holder risks
    # ========================================================================

    def test_small_holder_base_is_high_risk(self):
        result = self.analyzer.analyze(
            holder_data={
                "holder_count": 5,
                "complete_history": True,
            },
        )

        self.assertEqual(
            result.holder_risk_points,
            Decimal("15"),
        )

    def test_extreme_holder_concentration_is_critical(self):
        result = self.analyzer.analyze(
            holder_data={
                "holder_count": 1000,
                "top_10_holder_percentage": Decimal("95"),
                "complete_history": True,
            },
        )

        self.assertEqual(
            result.holder_risk_points,
            Decimal("15"),
        )

        finding = next(
            finding
            for finding in result.findings
            if finding.title == "Extreme holder concentration"
        )

        self.assertEqual(
            finding.severity,
            "critical",
        )

    def test_incomplete_holder_history_adds_risk(self):
        result = self.analyzer.analyze(
            holder_data={
                "holder_count": 1000,
                "top_10_holder_percentage": Decimal("20"),
                "complete_history": False,
            },
        )

        self.assertEqual(
            result.holder_risk_points,
            Decimal("3"),
        )

    def test_holder_deduction_is_capped(self):
        result = self.analyzer.analyze(
            holder_data={
                "holder_count": 1,
                "top_10_holder_percentage": Decimal("99"),
                "complete_history": False,
            },
        )

        self.assertLessEqual(
            result.holder_risk_points,
            Decimal("25"),
        )

    # ========================================================================
    # Demand risks
    # ========================================================================

    def test_no_market_activity_is_high_risk(self):
        result = self.analyzer.analyze(
            demand_data={
                "buy_count": 0,
                "sell_count": 0,
            },
        )

        self.assertEqual(
            result.demand_risk_points,
            Decimal("12"),
        )

        self.assertTrue(
            any(
                finding.title == "No observed market activity"
                for finding in result.findings
            )
        )

    def test_no_buys_is_high_risk(self):
        result = self.analyzer.analyze(
            demand_data={
                "buy_count": 0,
                "sell_count": 10,
            },
        )

        self.assertTrue(
            any(
                finding.title == "No observed buys"
                for finding in result.findings
            )
        )

    def test_few_unique_buyers_adds_risk(self):
        result = self.analyzer.analyze(
            demand_data={
                "buy_count": 20,
                "sell_count": 5,
                "unique_buyers": 2,
                "unique_sellers": 2,
            },
        )

        self.assertTrue(
            any(
                finding.title == "Very few unique buyers"
                for finding in result.findings
            )
        )

    def test_strong_sell_pressure_adds_risk(self):
        result = self.analyzer.analyze(
            demand_data={
                "buy_count": 50,
                "sell_count": 100,
                "unique_buyers": 20,
                "unique_sellers": 20,
                "demand_pressure": Decimal("-60"),
            },
        )

        self.assertTrue(
            any(
                finding.title == "Strong observed sell pressure"
                for finding in result.findings
            )
        )

    def test_sell_volume_dominance_adds_risk(self):
        result = self.analyzer.analyze(
            demand_data={
                "buy_count": 20,
                "sell_count": 20,
                "unique_buyers": 10,
                "unique_sellers": 10,
                "buy_volume": Decimal("100"),
                "sell_volume": Decimal("400"),
            },
        )

        self.assertTrue(
            any(
                finding.title == "Sell volume dominates"
                for finding in result.findings
            )
        )

    def test_seller_participation_dominance_adds_risk(self):
        result = self.analyzer.analyze(
            demand_data={
                "buy_count": 20,
                "sell_count": 20,
                "unique_buyers": 5,
                "unique_sellers": 20,
            },
        )

        self.assertTrue(
            any(
                finding.title == "Seller participation dominates"
                for finding in result.findings
            )
        )

    # ========================================================================
    # Score boundaries
    # ========================================================================

    def test_score_never_exceeds_one_hundred(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": True,
            },
            liquidity_data={
                "has_liquidity": True,
                "total_liquidity_usd": Decimal("1000000"),
                "liquidity_pool_count": 10,
                "liquidity_locked": True,
            },
            holder_data={
                "holder_count": 10000,
                "top_10_holder_percentage": Decimal("1"),
                "complete_history": True,
            },
            demand_data={
                "buy_count": 1000,
                "sell_count": 100,
                "unique_buyers": 500,
                "unique_sellers": 50,
            },
        )

        self.assertLessEqual(
            result.score,
            100,
        )

    def test_score_never_goes_below_zero(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": False,
                "unlimited_mint_detected": True,
                "blacklist_detected": True,
            },
            liquidity_data={
                "has_liquidity": False,
                "liquidity_pool_count": 1,
                "liquidity_locked": False,
            },
            holder_data={
                "holder_count": 1,
                "top_10_holder_percentage": Decimal("99"),
                "complete_history": False,
            },
            demand_data={
                "buy_count": 0,
                "sell_count": 100,
                "unique_buyers": 0,
                "unique_sellers": 100,
                "demand_pressure": Decimal("-100"),
                "buy_volume": Decimal("1"),
                "sell_volume": Decimal("100"),
            },
        )

        self.assertGreaterEqual(
            result.score,
            0,
        )

    # ========================================================================
    # Warnings
    # ========================================================================

    def test_critical_findings_generate_warning(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": False,
                "unlimited_mint_detected": True,
            },
        )

        self.assertTrue(
            any(
                "critical contract" in warning.lower()
                for warning in result.warnings
            )
        )

    def test_missing_analysis_data_generates_warnings(self):
        result = self.analyzer.analyze()

        expected_warnings = {
            "Contract analysis data was not supplied.",
            "Liquidity analysis data was not supplied.",
            "Holder analysis data was not supplied.",
            "Demand analysis data was not supplied.",
        }

        self.assertTrue(
            expected_warnings.issubset(
                set(result.warnings)
            )
        )

    def test_safe_profile_still_contains_safety_disclaimer(self):
        result = self.analyzer.analyze(
            contract_data={
                "contract_verified": True,
                "unlimited_mint_detected": False,
                "blacklist_detected": False,
            },
            liquidity_data={
                "total_liquidity_usd": Decimal("500000"),
                "liquidity_pool_count": 3,
                "liquidity_concentration_percentage": Decimal("40"),
                "has_liquidity": True,
                "liquidity_locked": True,
            },
            holder_data={
                "holder_count": 1000,
                "top_10_holder_percentage": Decimal("20"),
                "complete_history": True,
            },
            demand_data={
                "buy_count": 100,
                "sell_count": 50,
                "unique_buyers": 50,
                "unique_sellers": 30,
                "buy_volume": Decimal("100000"),
                "sell_volume": Decimal("40000"),
                "demand_pressure": Decimal("42.86"),
            },
        )

        self.assertTrue(
            any(
                "does not establish that the token is safe"
                in warning
                for warning in result.warnings
            )
        )