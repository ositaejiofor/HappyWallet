"""Tests for ownership-checked wallet selection across public pages."""

from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.http import Http404
from django.test import SimpleTestCase

from apps.transaction import views as transaction_views
from apps.wallet import views as wallet_views


class _WalletQuery:
    def __init__(self, *, default=None, selected=None) -> None:
        self.default = default
        self.selected = selected
        self.selected_pk = None

    def first(self):
        return self.default if self.selected_pk is None else self.selected

    def filter(self, *, pk):
        self.selected_pk = pk
        return self


class WalletSelectionTests(SimpleTestCase):
    def setUp(self) -> None:
        self.user = SimpleNamespace(pk=uuid4())
        self.wallet = SimpleNamespace(pk=uuid4())

    @patch.object(wallet_views, "_get_user_wallets")
    def test_wallet_page_uses_consistent_default(self, mock_wallets: Mock) -> None:
        mock_wallets.return_value = _WalletQuery(default=self.wallet)

        selected = wallet_views._get_user_wallet(self.user)

        self.assertIs(selected, self.wallet)

    @patch.object(transaction_views, "_get_user_wallets")
    def test_transaction_page_uses_consistent_default(
        self,
        mock_wallets: Mock,
    ) -> None:
        mock_wallets.return_value = _WalletQuery(default=self.wallet)

        selected = transaction_views._get_user_wallet(user=self.user)

        self.assertIs(selected, self.wallet)

    @patch.object(wallet_views, "_get_user_wallets")
    def test_owned_wallet_uuid_is_selected(self, mock_wallets: Mock) -> None:
        query = _WalletQuery(selected=self.wallet)
        mock_wallets.return_value = query

        selected = wallet_views._get_user_wallet(
            self.user,
            str(self.wallet.pk),
        )

        self.assertIs(selected, self.wallet)
        self.assertEqual(query.selected_pk, self.wallet.pk)

    @patch.object(transaction_views, "_get_user_wallets")
    def test_transaction_wallet_uuid_is_selected(
        self,
        mock_wallets: Mock,
    ) -> None:
        query = _WalletQuery(selected=self.wallet)
        mock_wallets.return_value = query

        selected = transaction_views._get_user_wallet(
            user=self.user,
            wallet_id=str(self.wallet.pk),
        )

        self.assertIs(selected, self.wallet)
        self.assertEqual(query.selected_pk, self.wallet.pk)

    @patch.object(wallet_views, "_get_user_wallets")
    def test_malformed_wallet_uuid_is_rejected(self, mock_wallets: Mock) -> None:
        mock_wallets.return_value = _WalletQuery()

        with self.assertRaises(Http404):
            wallet_views._get_user_wallet(self.user, "not-a-uuid")

    @patch.object(transaction_views, "_get_user_wallets")
    def test_unknown_or_foreign_wallet_is_rejected(
        self,
        mock_wallets: Mock,
    ) -> None:
        mock_wallets.return_value = _WalletQuery(selected=None)

        with self.assertRaises(Http404):
            transaction_views._get_user_wallet(
                user=self.user,
                wallet_id=str(uuid4()),
            )

    def test_wallet_query_is_scoped_to_authenticated_user(self) -> None:
        manager = Mock()
        selected = manager.select_related.return_value
        filtered = selected.filter.return_value
        filtered.order_by.return_value = "owned-wallet-query"

        with patch.object(wallet_views.Wallet, "objects", manager):
            result = wallet_views._get_user_wallets(self.user)

        selected.filter.assert_called_once_with(user=self.user)
        filtered.order_by.assert_called_once_with("-created_at", "-id")
        self.assertEqual(result, "owned-wallet-query")

    def test_transaction_query_is_scoped_to_authenticated_user(self) -> None:
        manager = Mock()
        selected = manager.select_related.return_value
        filtered = selected.filter.return_value
        filtered.order_by.return_value = "owned-wallet-query"

        with patch.object(transaction_views.Wallet, "objects", manager):
            result = transaction_views._get_user_wallets(user=self.user)

        selected.filter.assert_called_once_with(user=self.user)
        filtered.order_by.assert_called_once_with("-created_at", "-id")
        self.assertEqual(result, "owned-wallet-query")
