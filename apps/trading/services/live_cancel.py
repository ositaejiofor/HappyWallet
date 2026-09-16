"""Fail-closed Kraken live-order cancellation boundary."""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction

from ..models import Order, TradingAccount
from .kraken import (
    KrakenAdapter,
    KrakenAPIError,
    KrakenConfigurationError,
    KrakenRejectedError,
    KrakenTransportError,
)


class LiveCancellationError(Exception):
    """Raised when a live cancellation cannot be confirmed safely."""


class LiveCancellationService:
    """Cancel a submitted Kraken order without guessing its outcome."""

    def __init__(self, *, adapter=None):
        self.adapter = adapter or KrakenAdapter()

    @staticmethod
    def _validate(account, order):
        if not account.is_active:
            raise ValidationError("Trading account is inactive.")
        if account.mode != TradingAccount.Mode.LIVE:
            raise ValidationError("Live cancellation requires a live account.")
        if order.account_id != account.id:
            raise ValidationError("This order does not belong to the trading account.")
        if order.status not in {
            Order.Status.OPEN,
            Order.Status.PARTIALLY_FILLED,
        }:
            raise ValidationError("This live order cannot be cancelled.")
        if not str(order.exchange_order_id or "").strip():
            raise ValidationError("Order has no Kraken exchange order ID.")

    def _ensure_enabled(self):
        if not getattr(settings, "KRAKEN_LIVE_TRADING_ENABLED", False):
            raise LiveCancellationError("Kraken live trading is disabled.")
        try:
            self.adapter.assert_live_trading_enabled()
        except KrakenConfigurationError as exc:
            raise LiveCancellationError(str(exc)) from exc

    @staticmethod
    def _mark_unknown(order_id, message):
        with transaction.atomic():
            order = Order.objects.select_for_update().get(pk=order_id)
            order.status = Order.Status.CANCEL_UNKNOWN
            order.submission_error = message
            order.save(update_fields=["status", "submission_error", "updated_at"])
        return order

    def cancel(self, *, account, order):
        with transaction.atomic():
            locked = Order.objects.select_for_update().get(pk=order.pk)
            self._validate(account, locked)
            self._ensure_enabled()
            exchange_order_id = locked.exchange_order_id
            locked.status = Order.Status.CANCELLING
            locked.submission_error = ""
            locked.save(update_fields=["status", "submission_error", "updated_at"])

        try:
            result = self.adapter.cancel_order(
                exchange_order_id=exchange_order_id,
            )
        except KrakenRejectedError as exc:
            self._mark_unknown(locked.pk, str(exc))
            raise LiveCancellationError(
                "Kraken rejected the cancellation request; reconcile the order."
            ) from exc
        except (KrakenTransportError, KrakenAPIError) as exc:
            self._mark_unknown(locked.pk, str(exc))
            raise LiveCancellationError(
                "Kraken cancellation outcome is unknown; reconcile before retrying."
            ) from exc

        if not isinstance(result, dict):
            self._mark_unknown(locked.pk, "Kraken returned an invalid cancellation response.")
            raise LiveCancellationError(
                "Kraken cancellation outcome is unknown; reconcile before retrying."
            )

        try:
            count = int(result.get("count", 0))
        except (TypeError, ValueError):
            count = 0

        if count < 1:
            self._mark_unknown(locked.pk, "Kraken did not confirm an order cancellation.")
            raise LiveCancellationError(
                "Kraken did not confirm cancellation; reconcile the order."
            )

        with transaction.atomic():
            final = Order.objects.select_for_update().get(pk=locked.pk)
            if final.status != Order.Status.CANCELLING:
                raise LiveCancellationError(
                    "Order state changed while cancellation was in progress."
                )
            final.status = Order.Status.CANCELLED
            final.submission_error = ""
            final.save(update_fields=["status", "submission_error", "updated_at"])
        return final
