import uuid
from decimal import Decimal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction

from ..models import Order, TradingAccount, TradingPair
from .validation import validate_order


class OrderService:
    """
    Application service for creating and cancelling trading orders.

    This service deliberately has no access to:

        - private keys
        - seed phrases
        - wallet secrets
        - signing material
        - blockchain broadcasting
    """

    @staticmethod
    @transaction.atomic
    def create_order(
        *,
        account: TradingAccount,
        pair: TradingPair,
        side: str,
        order_type: str,
        quantity: Decimal,
        limit_price: Decimal | None = None,
    ) -> Order:

        if not account.is_active:
            raise ValidationError(
                "Trading account is inactive."
            )

        if account.mode == TradingAccount.Mode.LIVE:
            if not getattr(
                settings,
                "KRAKEN_LIVE_TRADING_ENABLED",
                False,
            ):
                raise ValidationError(
                    "Live trading is not enabled."
                )

            if not (
                getattr(settings, "KRAKEN_API_KEY", "")
                and getattr(settings, "KRAKEN_API_SECRET", "")
            ):
                raise ValidationError(
                    "Kraken live-trading credentials are not configured."
                )

        elif account.mode != TradingAccount.Mode.PAPER:
            raise ValidationError("Unsupported trading account mode.")

        validate_order(
            pair=pair,
            side=side,
            order_type=order_type,
            quantity=quantity,
            limit_price=limit_price,
        )

        return Order.objects.create(
            account=account,
            pair=pair,
            client_order_id=uuid.uuid4().hex,
            side=side,
            order_type=order_type,
            quantity=quantity,
            limit_price=limit_price,
            status=Order.Status.PENDING,
        )

    @staticmethod
    @transaction.atomic
    def cancel_order(
        *,
        account: TradingAccount,
        order: Order,
    ) -> Order:

        order = (
            Order.objects
            .select_for_update()
            .get(pk=order.pk)
        )

        if order.account_id != account.id:
            raise ValidationError(
                "This order does not belong to "
                "the trading account."
            )

        if order.status not in (
            Order.Status.PENDING,
            Order.Status.OPEN,
            Order.Status.PARTIALLY_FILLED,
        ):
            raise ValidationError(
                "This order cannot be cancelled."
            )

        if (
            account.mode == TradingAccount.Mode.LIVE
            and order.status != Order.Status.PENDING
        ):
            raise ValidationError(
                "Submitted live orders must be cancelled at Kraken "
                "and reconciled before their local status changes."
            )

        order.status = Order.Status.CANCELLED

        order.save(
            update_fields=[
                "status",
                "updated_at",
            ]
        )

        return order
