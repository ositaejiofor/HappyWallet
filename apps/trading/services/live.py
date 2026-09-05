"""
HappyWallet live trading execution boundary.

This service is the ONLY application-level boundary that should eventually
allow a Trading Order to reach a live exchange adapter.

Safety rules:
    - Paper accounts can never use this service.
    - Live trading must be explicitly enabled.
    - The order must belong to the supplied trading account.
    - Only valid, executable order states are accepted.
    - Kraken order submission remains disabled until the adapter and
      complete confirmation/risk boundary are implemented.
    - This service never accesses:
        * private keys
        * seed phrases
        * mnemonics
        * wallet secrets
        * blockchain signing material
"""


from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction

from ..models import Order, TradingAccount
from .kraken import (
    KrakenAdapter,
    KrakenConfigurationError,
)
from .validation import validate_order


class LiveExecutionError(Exception):
    """Base exception for live execution failures."""


class LiveTradingDisabledError(LiveExecutionError):
    """Raised when live trading is not explicitly enabled."""


class LiveExecutionService:
    """
    Safety boundary for live exchange execution.

    This class deliberately does NOT submit real orders yet.

    The intended execution path is:

        Trading Order
            ↓
        LiveExecutionService
            ↓
        validation
            ↓
        confirmation/risk checks
            ↓
        KrakenAdapter
            ↓
        Kraken

    Until the complete safety boundary is implemented, live submission
    remains blocked.
    """

    def __init__(
        self,
        *,
        adapter=None,
        confirmation_required=None,
    ):
        self.adapter = adapter or KrakenAdapter()

        if confirmation_required is None:
            confirmation_required = getattr(
                settings,
                "WALLET_REQUIRE_CONFIRMATION",
                True,
            )

        self.confirmation_required = bool(
            confirmation_required
        )

    @staticmethod
    def _ensure_account_is_live(
        *,
        account: TradingAccount,
    ):
        if not account.is_active:
            raise ValidationError(
                "Trading account is inactive."
            )

        if account.mode != TradingAccount.Mode.LIVE:
            raise ValidationError(
                "Live execution requires a live trading account."
            )

    @staticmethod
    def _ensure_order_belongs_to_account(
        *,
        account: TradingAccount,
        order: Order,
    ):
        if order.account_id != account.id:
            raise ValidationError(
                "This order does not belong to "
                "the trading account."
            )

    @staticmethod
    def _ensure_order_can_execute(
        *,
        order: Order,
    ):
        if order.status not in (
            Order.Status.PENDING,
            Order.Status.OPEN,
        ):
            raise ValidationError(
                "This order cannot be executed."
            )

    @staticmethod
    def _validate_order(
        *,
        order: Order,
    ):
        validate_order(
            pair=order.pair,
            side=order.side,
            order_type=order.order_type,
            quantity=order.quantity,
            limit_price=order.limit_price,
        )

    def _ensure_live_trading_enabled(self):
        """
        Enforce both application-level and adapter-level live guards.

        This method never enables live trading.
        """

        enabled = getattr(
            settings,
            "KRAKEN_LIVE_TRADING_ENABLED",
            False,
        )

        if not enabled:
            raise LiveTradingDisabledError(
                "Kraken live trading is disabled."
            )

        try:
            self.adapter.assert_live_trading_enabled()
        except KrakenConfigurationError as exc:
            raise LiveTradingDisabledError(
                str(exc)
            ) from exc

    @transaction.atomic
    def execute(
        self,
        *,
        account: TradingAccount,
        order: Order,
        confirmed=False,
    ):
        """
        Attempt live execution of an existing order.

        Real Kraken order submission is intentionally blocked until the
        complete live execution implementation is finished.

        Returns:
            Order

        Raises:
            ValidationError
            LiveTradingDisabledError
            LiveExecutionError
        """

        order = (
            Order.objects
            .select_for_update()
            .select_related(
                "account",
                "pair",
                "pair__base_asset",
                "pair__quote_asset",
            )
            .get(pk=order.pk)
        )

        self._ensure_account_is_live(
            account=account,
        )

        self._ensure_order_belongs_to_account(
            account=account,
            order=order,
        )

        self._ensure_order_can_execute(
            order=order,
        )

        self._validate_order(
            order=order,
        )

        if (
            self.confirmation_required
            and not confirmed
        ):
            raise ValidationError(
                "Live order confirmation is required."
            )

        self._ensure_live_trading_enabled()

        raise LiveExecutionError(
            "Live Kraken order execution is not implemented yet."
        )
