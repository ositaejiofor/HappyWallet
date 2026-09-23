"""Safety tests for the read-only TRON USDT receive flow."""

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.http import Http404
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import reverse

from apps.transaction.services.history import TransactionHistory, WalletTransaction
from apps.wallet import views
from apps.wallet.models import Wallet


class TronReceiveFlowTests(SimpleTestCase):
    ADDRESS = "TUoHaVjx7n5xz8LwPRDckgFrDWhMhuSuJM"
    CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.user = SimpleNamespace(is_authenticated=True)
        self.wallet = SimpleNamespace(
            pk=uuid4(),
            address=self.ADDRESS,
            network=SimpleNamespace(
                slug="tron-mainnet",
                name="Tron Mainnet",
                symbol="TRX",
            ),
        )

    def test_receive_routes_are_wallet_scoped(self) -> None:
        self.assertEqual(
            reverse("wallet:tron_receive_qr", args=[self.wallet.pk]),
            f"/wallet/{self.wallet.pk}/receive/tron-qr.svg",
        )
        self.assertEqual(
            reverse(
                "wallet:tron_usdt_receive_status",
                args=[self.wallet.pk],
            ),
            f"/wallet/{self.wallet.pk}/receive/usdt-status/",
        )

    @patch.object(views, "_get_wallet_address")
    @patch.object(views, "_get_receive_wallet")
    @patch.object(views.qrcode, "make")
    def test_qr_is_generated_locally_and_never_cached(
        self,
        mock_make: Mock,
        mock_get_wallet: Mock,
        mock_get_address: Mock,
    ) -> None:
        mock_get_wallet.return_value = self.wallet
        mock_get_address.return_value = self.ADDRESS
        mock_make.return_value.to_string.return_value = "<svg></svg>"
        request = self.factory.get("/wallet/receive/qr.svg")
        request.user = self.user

        response = views.tron_receive_qr(request, self.wallet.pk)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store, private")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        mock_make.assert_called_once_with(
            self.ADDRESS,
            image_factory=views.SvgPathFillImage,
        )

    @override_settings(TRON_USDT_CONTRACT_ADDRESS=CONTRACT)
    @patch.object(views, "_get_wallet_address")
    @patch.object(views, "_get_receive_wallet")
    @patch.object(views, "get_wallet_transaction_history")
    def test_status_exposes_confirmed_incoming_usdt_only(
        self,
        mock_history: Mock,
        mock_get_wallet: Mock,
        mock_get_address: Mock,
    ) -> None:
        mock_get_wallet.return_value = self.wallet
        mock_get_address.return_value = self.ADDRESS
        mock_history.return_value = TransactionHistory(
            transactions=(
                WalletTransaction(
                    transaction_hash="a" * 64,
                    transaction_type="receive",
                    status="confirmed",
                    network="TRON Mainnet",
                    amount=Decimal("15.25"),
                    symbol="USDT",
                    timestamp=1_700_000_000,
                ),
                WalletTransaction(
                    transaction_hash="b" * 64,
                    transaction_type="send",
                    status="confirmed",
                    network="TRON Mainnet",
                    amount=Decimal("2"),
                    symbol="USDT",
                ),
                WalletTransaction(
                    transaction_hash="c" * 64,
                    transaction_type="receive",
                    status="confirmed",
                    network="TRON Mainnet",
                    amount=Decimal("3"),
                    symbol="TRX",
                ),
            ),
            available=True,
        )
        request = self.factory.get("/wallet/receive/usdt-status/")
        request.user = self.user

        response = views.tron_usdt_receive_status(request, self.wallet.pk)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '"confirmed_deposit_count": 1')
        self.assertContains(response, '"amount": "15.25"')
        self.assertContains(response, self.CONTRACT)
        self.assertEqual(response["Cache-Control"], "no-store, private")

    @patch.object(views, "_get_receive_wallet")
    def test_post_is_rejected_before_receive_logic(
        self,
        mock_get_wallet: Mock,
    ) -> None:
        request = self.factory.post("/wallet/receive/usdt-status/")
        request.user = self.user

        response = views.tron_usdt_receive_status(request, self.wallet.pk)

        self.assertEqual(response.status_code, 405)
        mock_get_wallet.assert_not_called()

    def test_anonymous_qr_request_requires_login(self) -> None:
        request = self.factory.get("/wallet/receive/qr.svg")
        request.user = AnonymousUser()

        response = views.tron_receive_qr(request, self.wallet.pk)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])

    def test_receive_wallet_lookup_is_owned_active_and_tron_only(self) -> None:
        manager = Mock()
        selected = manager.select_related.return_value
        filtered = selected.filter.return_value
        filtered.first.return_value = None

        with patch.object(Wallet, "objects", manager):
            with self.assertRaises(Http404):
                views._get_receive_wallet(
                    user=self.user,
                    wallet_id=self.wallet.pk,
                )

        selected.filter.assert_called_once_with(
            pk=self.wallet.pk,
            user=self.user,
            status=Wallet.Status.ACTIVE,
        )

    def test_invalid_tron_address_is_rejected(self) -> None:
        with self.assertRaises(Http404):
            views._validate_tron_receive_address("0x-not-tron")

    def test_non_tron_wallet_is_not_accepted(self) -> None:
        wallet = SimpleNamespace(
            network=SimpleNamespace(
                slug="ethereum-mainnet",
                name="Ethereum Mainnet",
                symbol="ETH",
            )
        )

        self.assertFalse(views._is_tron_wallet(wallet))
