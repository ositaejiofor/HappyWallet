"""Read-only Kraken account dashboard service."""

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError

from ..models import TradingAccount
from .kraken import KrakenAdapter


class KrakenAccountDataError(Exception):
    """Raised when Kraken returns malformed account data."""


class KrakenAccountService:
    """
    Retrieve and normalize private Kraken account information.

    This service only calls read-only Kraken endpoints. It never submits,
    edits, or cancels orders.
    """

    CLOSED_ORDER_LIMIT = 25

    ASSET_NAMES = {
        "XXBT": "BTC",
        "XBT": "BTC",
        "XETH": "ETH",
        "ZUSD": "USD",
        "ZEUR": "EUR",
        "ZGBP": "GBP",
        "ZCAD": "CAD",
        "ZJPY": "JPY",
    }

    def __init__(self, *, adapter=None):
        self.adapter = adapter or KrakenAdapter()

    @staticmethod
    def _validate_account(account):
        if not account.is_active:
            raise ValidationError(
                "Trading account is inactive."
            )

        if account.mode != TradingAccount.Mode.LIVE:
            raise ValidationError(
                "Kraken account data requires a live trading account."
            )

    @classmethod
    def _asset_name(cls, value):
        asset = str(value or "").strip().upper()

        if not asset:
            return "UNKNOWN"

        if asset in cls.ASSET_NAMES:
            return cls.ASSET_NAMES[asset]

        return asset.removesuffix(".F")

    @staticmethod
    def _decimal(value):
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            return Decimal("0")

        if not amount.is_finite():
            return Decimal("0")

        return amount

    @staticmethod
    def _timestamp(value):
        try:
            timestamp = float(value)
        except (TypeError, ValueError):
            return None

        if timestamp <= 0:
            return None

        try:
            return datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc,
            )
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def _masked_order_id(value):
        order_id = str(value or "").strip()

        if not order_id:
            return "Unavailable"

        if len(order_id) <= 8:
            return order_id

        return f"••••{order_id[-8:]}"

    @classmethod
    def _normalize_balances(cls, payload):
        if not isinstance(payload, dict):
            raise KrakenAccountDataError(
                "Kraken returned invalid balance data."
            )

        balances = []

        for asset, raw_amount in payload.items():
            amount = cls._decimal(raw_amount)

            if amount == 0:
                continue

            balances.append(
                {
                    "asset": cls._asset_name(asset),
                    "amount": amount,
                }
            )

        return sorted(
            balances,
            key=lambda item: item["asset"],
        )

    @classmethod
    def _normalize_order(cls, order_id, payload):
        if not isinstance(payload, dict):
            return None

        description = payload.get("descr")

        if not isinstance(description, dict):
            description = {}

        return {
            "order_id": cls._masked_order_id(order_id),
            "pair": str(
                description.get("pair") or "Unknown"
            ),
            "side": str(
                description.get("type") or "unknown"
            ).lower(),
            "order_type": str(
                description.get("ordertype") or "unknown"
            ).lower(),
            "description": str(
                description.get("order") or ""
            ),
            "status": str(
                payload.get("status") or "unknown"
            ).lower(),
            "volume": cls._decimal(
                payload.get("vol")
            ),
            "executed_volume": cls._decimal(
                payload.get("vol_exec")
            ),
            "cost": cls._decimal(
                payload.get("cost")
            ),
            "fee": cls._decimal(
                payload.get("fee")
            ),
            "price": cls._decimal(
                payload.get("price")
                or description.get("price")
            ),
            "opened_at": cls._timestamp(
                payload.get("opentm")
            ),
            "closed_at": cls._timestamp(
                payload.get("closetm")
            ),
        }

    @classmethod
    def _normalize_orders(
        cls,
        payload,
        *,
        container,
        limit=None,
    ):
        if not isinstance(payload, dict):
            raise KrakenAccountDataError(
                "Kraken returned invalid order data."
            )

        raw_orders = payload.get(container, {})

        if not isinstance(raw_orders, dict):
            raise KrakenAccountDataError(
                "Kraken returned invalid order data."
            )

        orders = []

        for order_id, raw_order in raw_orders.items():
            order = cls._normalize_order(
                order_id,
                raw_order,
            )

            if order is not None:
                orders.append(order)

        orders.sort(
            key=lambda item: (
                item["closed_at"]
                or item["opened_at"]
                or datetime.min.replace(
                    tzinfo=timezone.utc
                )
            ),
            reverse=True,
        )

        if limit is not None:
            orders = orders[:limit]

        return orders

    def load(self, *, account):
        """
        Return normalized balances and order history.

        KRAKEN_LIVE_TRADING_ENABLED is intentionally not required because
        every Kraken operation used here is read-only.
        """
        self._validate_account(account)

        balances_payload = (
            self.adapter.get_account_balance()
        )

        open_orders_payload = (
            self.adapter.get_open_orders(
                trades=False
            )
        )

        closed_orders_payload = (
            self.adapter.get_closed_orders(
                trades=False
            )
        )

        return {
            "balances": self._normalize_balances(
                balances_payload
            ),
            "open_orders": self._normalize_orders(
                open_orders_payload,
                container="open",
            ),
            "closed_orders": self._normalize_orders(
                closed_orders_payload,
                container="closed",
                limit=self.CLOSED_ORDER_LIMIT,
            ),
            "retrieved_at": datetime.now(
                tz=timezone.utc
            ),
        }