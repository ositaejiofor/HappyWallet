import uuid

from django.core.exceptions import ValidationError
from django.db import transaction

from ..models import (
    Order,
    Trade,
    TradingAccount,
    TradingBalance,
)
from .validation import get_latest_price


class PaperTradingEngine:
    """
    Safe paper-trading execution engine.

    This engine is strictly isolated from real wallet execution.

    It never:

        - accesses a wallet
        - accesses private keys
        - accesses seed phrases or mnemonics
        - signs transactions
        - broadcasts transactions
        - moves real cryptocurrency

    It only updates paper-trading balances and records simulated trades.
    """

    @staticmethod
    @transaction.atomic
    def execute(order: Order) -> Trade:
        """
        Execute a pending/open order using the paper-trading engine.

        The entire operation is atomic. If any validation fails or an
        exception occurs, all balance/order changes are rolled back.

        Returns:
            Trade: The newly created simulated trade.

        Raises:
            ValidationError:
                If the account is not in paper mode, the order cannot
                be executed, the limit price is not satisfied, or the
                account has insufficient funds.
        """

        # Lock the order so that two requests cannot execute the same
        # order simultaneously.
        order = (
            Order.objects
            .select_for_update()
            .select_related(
                "account",
                "pair__base_asset",
                "pair__quote_asset",
            )
            .get(pk=order.pk)
        )

        # PaperTradingEngine must never execute live orders.
        if order.account.mode != TradingAccount.Mode.PAPER:
            raise ValidationError(
                "Paper engine can only execute paper orders."
            )

        # Only pending and open orders are executable.
        if order.status not in (
            Order.Status.PENDING,
            Order.Status.OPEN,
        ):
            raise ValidationError(
                "This order cannot be executed."
            )

        # Retrieve the current market price through the validation/
        # pricing boundary.
        price = get_latest_price(order.pair)

        # Validate limit-order price conditions.
        if order.order_type == Order.OrderType.LIMIT:

            if order.side == Order.Side.BUY:
                if price > order.limit_price:
                    raise ValidationError(
                        "Current price is above the "
                        "buy limit price."
                    )

            elif order.side == Order.Side.SELL:
                if price < order.limit_price:
                    raise ValidationError(
                        "Current price is below the "
                        "sell limit price."
                    )

        base_asset = order.pair.base_asset
        quote_asset = order.pair.quote_asset

        # Lock both balances before modifying them.
        base_balance, _ = (
            TradingBalance.objects
            .select_for_update()
            .get_or_create(
                account=order.account,
                asset=base_asset,
            )
        )

        quote_balance, _ = (
            TradingBalance.objects
            .select_for_update()
            .get_or_create(
                account=order.account,
                asset=quote_asset,
            )
        )

        # Total quote-asset value of the trade.
        notional = order.quantity * price

        if order.side == Order.Side.BUY:

            # BUY:
            #   quote asset decreases
            #   base asset increases
            if quote_balance.available < notional:
                raise ValidationError(
                    f"Insufficient "
                    f"{quote_asset.symbol.upper()} "
                    f"balance."
                )

            quote_balance.available -= notional
            base_balance.available += order.quantity

        elif order.side == Order.Side.SELL:

            # SELL:
            #   base asset decreases
            #   quote asset increases
            if base_balance.available < order.quantity:
                raise ValidationError(
                    f"Insufficient "
                    f"{base_asset.symbol.upper()} "
                    f"balance."
                )

            base_balance.available -= order.quantity
            quote_balance.available += notional

        else:
            raise ValidationError(
                "Unsupported order side."
            )

        # Persist both updated balances.
        quote_balance.save(
            update_fields=[
                "available",
                "updated_at",
            ]
        )

        base_balance.save(
            update_fields=[
                "available",
                "updated_at",
            ]
        )

        # Create the simulated trade record.
        trade = Trade.objects.create(
            order=order,
            execution_id=f"paper-{uuid.uuid4().hex}",
            quantity=order.quantity,
            price=price,
        )

        # Mark the order as completely filled.
        order.filled_quantity = order.quantity
        order.average_fill_price = price
        order.status = Order.Status.FILLED

        order.save(
            update_fields=[
                "filled_quantity",
                "average_fill_price",
                "status",
                "updated_at",
            ]
        )

        return trade
