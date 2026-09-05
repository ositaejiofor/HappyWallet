"""
Tests for the application-level transaction-history service.

These tests operate entirely at the application boundary.

Provider/network calls are mocked, therefore this suite:

- never contacts a real blockchain RPC;
- never requires RPC credentials;
- never exposes wallet secrets to the provider;
- verifies wallet/network validation;
- verifies Ethereum network selection;
- verifies adapter delegation;
- verifies provider failure handling;
- verifies provider-result validation;
- verifies DTO conversion;
- verifies DTO immutability;
- verifies the public-wallet security boundary.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from apps.transaction.services import history as history_service
from apps.transaction.services.history import (
    TransactionHistory,
    WalletTransaction,
    get_wallet_transaction_history,
)
from apps.transaction.services.networks.ethereum import (
    EthereumTransaction,
    EthereumTransactionHistory,
)


class TransactionHistoryServiceTests(SimpleTestCase):
    """Unit tests for the application transaction-history boundary."""

    # ========================================================================
    # SAFE TEST DATA
    # ========================================================================

    ADDRESS = "0x1111111111111111111111111111111111111111"

    # Deliberately invalid endpoint.
    # Tests must never contact a real provider.
    RPC_URL = "https://example.invalid/ethereum"

    BLOCK_LIMIT = 5

    TRANSACTION_HASH = (
        "0xaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaa"
    )

    # ========================================================================
    # FIXTURES
    # ========================================================================

    @classmethod
    def _ethereum_network(
        cls,
        **overrides,
    ) -> SimpleNamespace:
        """Return a minimal Ethereum network test double."""

        values = {
            "slug": "ethereum-mainnet",
            "name": "Ethereum Mainnet",
        }
        values.update(overrides)

        return SimpleNamespace(**values)

    @classmethod
    def _ethereum_wallet(
        cls,
        **overrides,
    ) -> SimpleNamespace:
        """Return a minimal public wallet test double."""

        values = {
            "address": cls.ADDRESS,
            "network": cls._ethereum_network(),
        }
        values.update(overrides)

        return SimpleNamespace(**values)

    @classmethod
    def _ethereum_wallet_with_secrets(
        cls,
    ) -> SimpleNamespace:
        """
        Return a wallet containing deliberately injected sensitive
        attributes.

        The service must never access or forward these attributes.
        """

        wallet = cls._ethereum_wallet()

        wallet.private_key = "must-not-be-used"
        wallet.mnemonic = "must-not-be-used"
        wallet.encrypted_private_key = "must-not-be-used"

        return wallet

    @classmethod
    def _ethereum_transaction(
        cls,
        **overrides,
    ) -> EthereumTransaction:
        """Return a deterministic provider transaction DTO."""

        values = {
            "transaction_hash": cls.TRANSACTION_HASH,
            "transaction_type": "transfer",
            "status": "confirmed",
            "network": "Ethereum Mainnet",
            "amount": Decimal("1.5"),
            "symbol": "ETH",
            "block_number": 100,
            "timestamp": 1_700_000_000,
        }
        values.update(overrides)

        return EthereumTransaction(**values)

    @staticmethod
    def _provider_history(
        *,
        available: bool = True,
        transactions: tuple[EthereumTransaction, ...] = (),
    ) -> EthereumTransactionHistory:
        """Return a deterministic Ethereum adapter response."""

        return EthereumTransactionHistory(
            transactions=transactions,
            available=available,
        )

    def _mock_ethereum_configuration(
        self,
        mock_settings: Mock,
        *,
        rpc_url: str | None = None,
        block_limit: int | None = None,
    ) -> None:
        """Configure the settings mock for Ethereum tests."""

        mock_settings.ETHEREUM_RPC_URL = (
            self.RPC_URL
            if rpc_url is None
            else rpc_url
        )

        mock_settings.TRANSACTION_HISTORY_BLOCK_LIMIT = (
            self.BLOCK_LIMIT
            if block_limit is None
            else block_limit
        )

    # ========================================================================
    # WALLET VALIDATION
    # ========================================================================

    def test_none_wallet_is_unavailable(self) -> None:
        """A missing wallet cannot have transaction history."""

        result = get_wallet_transaction_history(
            wallet=None,
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    def test_wallet_without_address_is_unavailable(self) -> None:
        """A wallet without a usable public address is unavailable."""

        wallet = self._ethereum_wallet(
            address="",
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    def test_whitespace_only_address_is_unavailable(self) -> None:
        """Whitespace-only addresses must not reach the provider."""

        wallet = self._ethereum_wallet(
            address="   ",
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    def test_wallet_without_network_is_unavailable(self) -> None:
        """A wallet without network configuration is unavailable."""

        wallet = self._ethereum_wallet(
            network=None,
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    def test_wallet_without_network_identifier_is_unavailable(
        self,
    ) -> None:
        """A network without a usable identifier is unavailable."""

        wallet = self._ethereum_wallet(
            network=SimpleNamespace(),
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    # ========================================================================
    # NETWORK SELECTION
    # ========================================================================

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_unsupported_network_is_unavailable(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """
        Unsupported networks fail closed.

        The provider must never be contacted.
        """

        wallet = self._ethereum_wallet(
            network=SimpleNamespace(
                slug="bitcoin-mainnet",
                name="Bitcoin Mainnet",
            ),
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())
        mock_get_history.assert_not_called()
        mock_settings.ETHEREUM_RPC_URL.assert_not_called = None

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_ethereum_network_is_selected_by_slug(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Ethereum Mainnet is selected from the network slug."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = self._provider_history()

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

        mock_get_history.assert_called_once_with(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=self.BLOCK_LIMIT,
        )

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_ethereum_network_can_be_identified_by_name(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Ethereum can be identified from the public network name."""

        self._mock_ethereum_configuration(
            mock_settings,
            block_limit=1,
        )

        mock_get_history.return_value = self._provider_history()

        wallet = self._ethereum_wallet(
            network=SimpleNamespace(
                name="Ethereum",
            ),
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

        mock_get_history.assert_called_once_with(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=1,
        )

    # ========================================================================
    # ETHEREUM PROVIDER DELEGATION
    # ========================================================================

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_ethereum_history_is_delegated_to_adapter(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Ethereum history retrieval is delegated to the adapter."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        provider_transaction = self._ethereum_transaction()

        mock_get_history.return_value = self._provider_history(
            transactions=(provider_transaction,),
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        mock_get_history.assert_called_once_with(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=self.BLOCK_LIMIT,
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 1)

    # ========================================================================
    # DTO CONVERSION
    # ========================================================================

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_transaction_is_converted_to_application_dto(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Provider DTOs are converted into application DTOs."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        provider_transaction = self._ethereum_transaction()

        mock_get_history.return_value = self._provider_history(
            transactions=(provider_transaction,),
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 1)

        transaction = result.transactions[0]

        self.assertIsInstance(
            transaction,
            WalletTransaction,
        )

        expected_values = {
            "transaction_hash": provider_transaction.transaction_hash,
            "transaction_type": "transfer",
            "status": "confirmed",
            "network": "Ethereum Mainnet",
            "amount": Decimal("1.5"),
            "symbol": "ETH",
            "block_number": 100,
            "timestamp": 1_700_000_000,
        }

        for attribute, expected in expected_values.items():
            with self.subTest(attribute=attribute):
                self.assertEqual(
                    getattr(transaction, attribute),
                    expected,
                )

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_multiple_provider_transactions_are_converted(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """All valid provider transactions are converted."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        first = self._ethereum_transaction()

        second = self._ethereum_transaction(
            transaction_hash=(
                "0xbbbbbbbbbbbbbbbbbbbbbbbb"
                "bbbbbbbbbbbbbbbbbbbbbbbb"
                "bbbbbbbb"
            ),
            amount=Decimal("2.25"),
        )

        mock_get_history.return_value = self._provider_history(
            transactions=(first, second),
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertTrue(result.available)
        self.assertEqual(len(result.transactions), 2)

        self.assertEqual(
            result.transactions[0].transaction_hash,
            first.transaction_hash,
        )

        self.assertEqual(
            result.transactions[1].transaction_hash,
            second.transaction_hash,
        )

    # ========================================================================
    # PROVIDER AVAILABILITY
    # ========================================================================

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_successful_empty_history_is_available(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """An empty but successful provider response is available."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = self._provider_history()

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertTrue(result.available)
        self.assertEqual(result.transactions, ())

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_unavailable_result_is_propagated_safely(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """An unavailable provider result becomes unavailable history."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = self._provider_history(
            available=False,
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_missing_rpc_url_is_unavailable(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Missing RPC configuration prevents provider access."""

        self._mock_ethereum_configuration(
            mock_settings,
            rpc_url="",
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

        mock_get_history.assert_not_called()

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_runtime_error_is_handled_safely(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Provider RuntimeError must not escape the service boundary."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.side_effect = RuntimeError(
            "provider failure",
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_value_error_is_handled_safely(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """Provider ValueError must not escape the service boundary."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.side_effect = ValueError(
            "invalid provider response",
        )

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_returns_none_is_unavailable(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """A None provider result must fail closed."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = None

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_returns_invalid_result_is_unavailable(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """An invalid provider result must fail closed."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = object()

        result = get_wallet_transaction_history(
            wallet=self._ethereum_wallet(),
        )

        self.assertFalse(result.available)
        self.assertEqual(result.transactions, ())

    # ========================================================================
    # DTO CONTRACT
    # ========================================================================

    def test_transaction_history_is_immutable(self) -> None:
        """TransactionHistory must remain immutable."""

        result = TransactionHistory(
            transactions=(),
            available=True,
        )

        with self.assertRaises(AttributeError):
            result.available = False

    def test_wallet_transaction_is_immutable(self) -> None:
        """WalletTransaction must remain immutable."""

        transaction = WalletTransaction(
            transaction_hash=self.TRANSACTION_HASH,
            transaction_type="transfer",
            status="confirmed",
            network="Ethereum Mainnet",
        )

        with self.assertRaises(AttributeError):
            transaction.status = "failed"

    def test_transaction_history_normalizes_transactions_to_tuple(
        self,
    ) -> None:
        """TransactionHistory must expose transactions as a tuple."""

        transaction = WalletTransaction(
            transaction_hash=self.TRANSACTION_HASH,
            transaction_type="transfer",
            status="confirmed",
            network="Ethereum Mainnet",
        )

        result = TransactionHistory(
            transactions=[transaction],
            available=True,
        )

        self.assertIsInstance(
            result.transactions,
            tuple,
        )

        self.assertEqual(
            result.transactions,
            (transaction,),
        )

    def test_transaction_history_normalizes_available_to_bool(
        self,
    ) -> None:
        """TransactionHistory must normalize availability to bool."""

        result = TransactionHistory(
            transactions=(),
            available=1,
        )

        self.assertIs(
            result.available,
            True,
        )

    # ========================================================================
    # SECURITY BOUNDARY
    # ========================================================================

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_only_public_wallet_address_is_passed_to_provider(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """
        The Ethereum adapter receives only public wallet information.

        Private wallet material must never be passed to the provider.
        """

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = self._provider_history()

        wallet = self._ethereum_wallet_with_secrets()

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertTrue(result.available)

        mock_get_history.assert_called_once_with(
            rpc_url=self.RPC_URL,
            address=self.ADDRESS,
            block_limit=self.BLOCK_LIMIT,
        )

        call_kwargs = mock_get_history.call_args.kwargs

        self.assertEqual(
            set(call_kwargs),
            {
                "rpc_url",
                "address",
                "block_limit",
            },
        )

        self.assertNotIn(
            "private_key",
            call_kwargs,
        )

        self.assertNotIn(
            "mnemonic",
            call_kwargs,
        )

        self.assertNotIn(
            "encrypted_private_key",
            call_kwargs,
        )

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_provider_never_receives_wallet_object(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """The provider must receive public values, not the Wallet object."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        mock_get_history.return_value = self._provider_history()

        wallet = self._ethereum_wallet_with_secrets()

        get_wallet_transaction_history(
            wallet=wallet,
        )

        call_kwargs = mock_get_history.call_args.kwargs

        for value in call_kwargs.values():
            self.assertIsNot(
                value,
                wallet,
            )

    @patch.object(history_service, "get_transaction_history")
    @patch.object(history_service, "settings")
    def test_missing_public_address_prevents_provider_access(
        self,
        mock_settings: Mock,
        mock_get_history: Mock,
    ) -> None:
        """An unusable public address must fail before provider access."""

        self._mock_ethereum_configuration(
            mock_settings,
        )

        wallet = self._ethereum_wallet(
            address=None,
        )

        result = get_wallet_transaction_history(
            wallet=wallet,
        )

        self.assertFalse(result.available)
        mock_get_history.assert_not_called()
