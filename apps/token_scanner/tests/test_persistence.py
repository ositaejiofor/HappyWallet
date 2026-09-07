from decimal import Decimal

from django.test import TestCase

from apps.token_scanner.models import Token, TokenAlert, TokenScan
from apps.token_scanner.services.contract import ContractAnalysis
from apps.token_scanner.services.demand import DemandAnalysis
from apps.token_scanner.services.holders import HolderAnalysis
from apps.token_scanner.services.liquidity import LiquidityAnalysis
from apps.token_scanner.services.persistence import TokenScanPersistence
from apps.token_scanner.services.risk import RiskAnalysis
from apps.token_scanner.services.scanner import TokenScanResult


class TokenScanPersistenceTests(TestCase):
    """Tests for persisting token scan results and generated alerts."""

    DEFAULT_ADDRESS = "0x0000000000000000000000000000000000000001"
    DEFAULT_FROM_BLOCK = 100
    DEFAULT_TO_BLOCK = 200

    def _result(
        self,
        *,
        address=DEFAULT_ADDRESS,
        symbol="TEST",
        name="Test Token",
        liquidity=Decimal("50000"),
        holders=100,
        top10=Decimal("25"),
        buys=20,
        sells=10,
        risk_score=80,
        mint=False,
        blacklist=False,
        verified=True,
        demand_pressure=Decimal("33.33"),
    ):
        """Build a realistic TokenScanResult for persistence tests."""

        contract = ContractAnalysis(
            address=address,
            is_contract=True,
            verified=verified,
            is_erc20_like=True,
            decimals=18,
            name=name,
            symbol=symbol,
            owner_function_detected=False,
            mint_function_detected=mint,
            unlimited_mint_detected=mint,
            blacklist_function_detected=blacklist,
            pause_function_detected=False,
            fee_control_detected=False,
            warnings=(),
            raw_code_size=1000,
        )

        liquidity_analysis = LiquidityAnalysis(
            token_address=address,
            pools=(),
            total_liquidity_usd=liquidity,
            deepest_pool_address=None,
            liquidity_pool_count=1 if liquidity is not None else 0,
            has_liquidity=(
                liquidity is not None and liquidity > 0
            ),
            liquidity_concentration_percentage=(
                Decimal("100")
                if liquidity is not None
                else None
            ),
            warnings=(),
        )

        holder_analysis = HolderAnalysis(
            token_address=address,
            scanned_from_block=self.DEFAULT_FROM_BLOCK,
            scanned_to_block=self.DEFAULT_TO_BLOCK,
            holder_count=holders,
            top_10_holder_percentage=top10,
            total_observed_balance=Decimal("1000000"),
            complete_history=True,
            warnings=(),
        )

        demand_analysis = DemandAnalysis(
            token_address=address,
            scanned_from_block=self.DEFAULT_FROM_BLOCK,
            scanned_to_block=self.DEFAULT_TO_BLOCK,
            buy_count=buys,
            sell_count=sells,
            transfer_count=0,
            mint_count=0,
            burn_count=0,
            unique_buyers=10,
            unique_sellers=5,
            buy_volume=Decimal("200"),
            sell_volume=Decimal("100"),
            total_observed_volume=Decimal("300"),
            buy_sell_ratio=Decimal("2"),
            buy_volume_ratio=Decimal("2"),
            demand_pressure=demand_pressure,
            warnings=(),
        )

        risk = RiskAnalysis(
            score=risk_score,
            rating="lower_observed_risk",
            contract_risk_points=Decimal("0"),
            liquidity_risk_points=Decimal("0"),
            holder_risk_points=Decimal("0"),
            demand_risk_points=Decimal("0"),
            findings=(),
            warnings=(),
        )

        return TokenScanResult(
            token_address=address,
            contract=contract,
            liquidity=liquidity_analysis,
            holders=holder_analysis,
            demand=demand_analysis,
            risk=risk,
            warnings=(),
        )

    @staticmethod
    def _alerts_of_type(alerts, alert_type):
        """Return alerts matching a specific alert type."""
        return [
            alert
            for alert in alerts
            if alert.alert_type == alert_type
        ]

    def test_new_scan_creates_token_and_snapshot(self):
        result = self._result()

        persisted = TokenScanPersistence().persist(result)

        self.assertIsNotNone(persisted.token.pk)
        self.assertIsNotNone(persisted.scan.pk)

        self.assertEqual(Token.objects.count(), 1)
        self.assertEqual(TokenScan.objects.count(), 1)

        token = persisted.token

        self.assertEqual(token.symbol, "TEST")
        self.assertEqual(token.name, "Test Token")
        self.assertEqual(token.decimals, 18)
        self.assertEqual(token.liquidity_usd, Decimal("50000"))
        self.assertEqual(token.holder_count, 100)
        self.assertEqual(token.buy_count_24h, 20)
        self.assertEqual(token.sell_count_24h, 10)
        self.assertEqual(token.risk_score, 80)

    def test_new_token_generates_new_token_alert(self):
        result = self._result()

        persisted = TokenScanPersistence().persist(result)

        alerts = self._alerts_of_type(
            persisted.alerts,
            TokenAlert.AlertType.NEW_TOKEN,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0].severity,
            TokenAlert.Severity.INFO,
        )

    def test_second_scan_updates_existing_token(self):
        persistence = TokenScanPersistence()

        first = self._result(
            liquidity=Decimal("50000"),
            holders=100,
            risk_score=80,
        )

        second = self._result(
            liquidity=Decimal("60000"),
            holders=120,
            risk_score=80,
        )

        persistence.persist(first)
        persistence.persist(second)

        self.assertEqual(Token.objects.count(), 1)
        self.assertEqual(TokenScan.objects.count(), 2)

        token = Token.objects.get()

        self.assertEqual(token.liquidity_usd, Decimal("60000"))
        self.assertEqual(token.holder_count, 120)

    def test_previous_scan_remains_unchanged(self):
        persistence = TokenScanPersistence()

        first_result = self._result(
            liquidity=Decimal("50000"),
            holders=100,
        )

        second_result = self._result(
            liquidity=Decimal("60000"),
            holders=150,
        )

        first = persistence.persist(first_result)
        persistence.persist(second_result)

        first.scan.refresh_from_db()

        self.assertEqual(
            first.scan.liquidity_usd,
            Decimal("50000"),
        )
        self.assertEqual(first.scan.holder_count, 100)

    def test_holder_growth_creates_alert(self):
        persistence = TokenScanPersistence()

        persistence.persist(
            self._result(
                holders=100,
                liquidity=Decimal("50000"),
            )
        )

        second = persistence.persist(
            self._result(
                holders=150,
                liquidity=Decimal("50000"),
            )
        )

        alerts = self._alerts_of_type(
            second.alerts,
            TokenAlert.AlertType.HOLDER_GROWTH,
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("increased", alerts[0].message)

    def test_liquidity_change_creates_alert(self):
        persistence = TokenScanPersistence()

        persistence.persist(
            self._result(
                liquidity=Decimal("100000"),
            )
        )

        second = persistence.persist(
            self._result(
                liquidity=Decimal("70000"),
            )
        )

        alerts = self._alerts_of_type(
            second.alerts,
            TokenAlert.AlertType.LIQUIDITY_CHANGE,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0].severity,
            TokenAlert.Severity.WARNING,
        )

    def test_large_risk_increase_creates_alert(self):
        persistence = TokenScanPersistence()

        persistence.persist(
            self._result(risk_score=80)
        )

        second = persistence.persist(
            self._result(risk_score=50)
        )

        alerts = self._alerts_of_type(
            second.alerts,
            TokenAlert.AlertType.RISK_CHANGE,
        )

        self.assertEqual(len(alerts), 1)

    def test_contract_warnings_create_alerts(self):
        result = self._result(
            mint=True,
            blacklist=True,
        )

        persisted = TokenScanPersistence().persist(result)

        alerts = self._alerts_of_type(
            persisted.alerts,
            TokenAlert.AlertType.CONTRACT_WARNING,
        )

        self.assertEqual(len(alerts), 2)

        severities = {
            alert.severity
            for alert in alerts
        }

        self.assertEqual(
            severities,
            {TokenAlert.Severity.CRITICAL},
        )

    def test_missing_usd_data_is_not_fabricated(self):
        result = self._result(liquidity=None)

        persisted = TokenScanPersistence().persist(result)

        persisted.token.refresh_from_db()
        persisted.scan.refresh_from_db()

        self.assertIsNone(persisted.token.liquidity_usd)
        self.assertIsNone(persisted.scan.liquidity_usd)
        self.assertIsNone(persisted.scan.market_cap_usd)
        self.assertIsNone(persisted.scan.volume_24h_usd)
