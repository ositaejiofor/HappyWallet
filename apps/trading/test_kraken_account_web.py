"""Web-boundary tests for the read-only Kraken dashboard."""

from datetime import datetime, timezone
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import TradingAccount
from .services.kraken import KrakenAPIError


User = get_user_model()


class KrakenAccountDashboardTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="kraken-reader",
            email="kraken-reader@example.com",
            password="test-password",
        )

        self.account = TradingAccount.objects.create(
            user=self.user,
            name="Read-only Kraken Account",
            mode=TradingAccount.Mode.LIVE,
            is_active=True,
        )

        self.url = reverse(
            "trading:kraken_account"
        )

    def test_login_is_required(self):
        response = self.client.get(
            self.url
        )

        self.assertEqual(
            response.status_code,
            302,
        )

    @patch(
        "apps.trading.views.KrakenAccountService"
    )
    def test_live_account_can_view_dashboard(
        self,
        service_class,
    ):
        service_class.return_value.load.return_value = {
            "balances": [
                {
                    "asset": "BTC",
                    "amount": "0.5",
                },
            ],
            "open_orders": [],
            "closed_orders": [],
            "retrieved_at": datetime.now(
                tz=timezone.utc
            ),
        }

        self.client.force_login(
            self.user
        )

        response = self.client.get(
            self.url
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Read-only Kraken access",
        )

        self.assertContains(
            response,
            "BTC",
        )

        service_class.return_value.load.assert_called_once_with(
            account=self.account
        )

    @patch(
        "apps.trading.views.KrakenAccountService"
    )
    def test_paper_account_is_forbidden_before_service_call(
        self,
        service_class,
    ):
        self.account.mode = TradingAccount.Mode.PAPER

        self.account.save(
            update_fields=["mode"]
        )

        self.client.force_login(
            self.user
        )

        response = self.client.get(
            self.url
        )

        self.assertEqual(
            response.status_code,
            403,
        )

        service_class.assert_not_called()

    @patch(
        "apps.trading.views.KrakenAccountService"
    )
    def test_inactive_account_is_forbidden(
        self,
        service_class,
    ):
        self.account.is_active = False

        self.account.save(
            update_fields=["is_active"]
        )

        self.client.force_login(
            self.user
        )

        response = self.client.get(
            self.url
        )

        self.assertEqual(
            response.status_code,
            403,
        )

        service_class.assert_not_called()

    @patch(
        "apps.trading.views.KrakenAccountService"
    )
    def test_kraken_failure_is_displayed_safely(
        self,
        service_class,
    ):
        service_class.return_value.load.side_effect = (
            KrakenAPIError(
                "Sensitive upstream detail"
            )
        )

        self.client.force_login(
            self.user
        )

        response = self.client.get(
            self.url
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            (
                "Kraken account information is "
                "temporarily unavailable."
            ),
        )

        self.assertNotContains(
            response,
            "Sensitive upstream detail",
        )

    @patch(
        "apps.trading.views.KrakenAccountService"
    )
    def test_response_is_not_cacheable(
        self,
        service_class,
    ):
        service_class.return_value.load.return_value = {
            "balances": [],
            "open_orders": [],
            "closed_orders": [],
            "retrieved_at": datetime.now(
                tz=timezone.utc
            ),
        }

        self.client.force_login(
            self.user
        )

        response = self.client.get(
            self.url
        )

        self.assertEqual(
            response["Cache-Control"],
            "private, no-store, max-age=0",
        )

        self.assertEqual(
            response["Pragma"],
            "no-cache",
        )