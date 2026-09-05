from decimal import Decimal

from django.core.exceptions import ValidationError

from apps.market.models import MarketPrice

from ..models import Order, TradingPair


def get_latest_price(pair: TradingPair) -> Decimal:
    """
    Return the latest known USD market price for the base asset.

    This is suitable for the initial paper-trading engine.
    Live trading will later obtain pair-specific prices from an
    execution/liquidity provider.
    """

    latest = (
        MarketPrice.objects
        .filter(asset=pair.base_asset)
        .order_by("-captured_at")
        .first()
    )

    if latest is None:
        raise ValidationError(
            f"No market price is available for "
            f"{pair.base_asset.symbol.upper()}."
        )

    if latest.price_usd <= 0:
        raise ValidationError(
            "The current market price is invalid."
        )

    return latest.price_usd


def validate_order(
    *,
    pair: TradingPair,
    side: str,
    order_type: str,
    quantity: Decimal,
    limit_price: Decimal | None = None,
):
    if not pair.is_active:
        raise ValidationError(
            "This trading pair is currently disabled."
        )

    if side not in Order.Side.values:
        raise ValidationError(
            "Invalid order side."
        )

    if order_type not in Order.OrderType.values:
        raise ValidationError(
            "Invalid order type."
        )

    if quantity <= 0:
        raise ValidationError(
            "Order quantity must be greater than zero."
        )

    if quantity < pair.min_order_quantity:
        raise ValidationError(
            f"Minimum order quantity is "
            f"{pair.min_order_quantity}."
        )

    if (
        pair.max_order_quantity is not None
        and quantity > pair.max_order_quantity
    ):
        raise ValidationError(
            f"Maximum order quantity is "
            f"{pair.max_order_quantity}."
        )

    if order_type == Order.OrderType.LIMIT:
        if limit_price is None:
            raise ValidationError(
                "Limit orders require a limit price."
            )

        if limit_price <= 0:
            raise ValidationError(
                "Limit price must be greater than zero."
            )

    if (
        order_type == Order.OrderType.MARKET
        and limit_price is not None
    ):
        raise ValidationError(
            "Market orders cannot have a limit price."
        )
        