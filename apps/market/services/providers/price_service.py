"""
HappyWallet market-price application service.

This service imports, stores and retrieves public cryptocurrency
market information.

Security boundary
-----------------
- Never requests private keys.
- Never signs transactions.
- Never broadcasts transactions.
- Never automatically buys or sells assets.
"""

from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.db import transaction
from django.db.models import Prefetch

from apps.market.models import (
    MarketAsset,
    MarketPrice,
)

from .coingecko import CoinGeckoProvider


class MarketPriceService:
    """
    Import and retrieve public cryptocurrency market data.
    """

    DEFAULT_LIMIT = 100
    MAX_LIMIT = 250

    def __init__(
        self,
        provider=None,
    ):
        """
        Create the market-price service.

        A provider can be supplied during testing. Otherwise, the
        configured CoinGecko provider is used.
        """

        if provider is not None:
            self.provider = provider
            return

        api_key = getattr(
            settings,
            "COINGECKO_API_KEY",
            "",
        )

        timeout = getattr(
            settings,
            "MARKET_PROVIDER_TIMEOUT",
            10,
        )

        self.provider = CoinGeckoProvider(
            api_key=api_key,
            timeout=timeout,
        )


    @staticmethod
    def _decimal(value):
        """
        Convert a provider value into Decimal safely.

        Returns None when the provider value is absent or invalid.
        """

        if value is None:
            return None

        try:
            return Decimal(str(value))

        except (
            InvalidOperation,
            ValueError,
            TypeError,
        ):
            return None


    @staticmethod
    def _positive_integer(
        value,
        *,
        default,
        maximum,
    ):
        """
        Convert and constrain a positive integer option.
        """

        try:
            value = int(value)

        except (
            TypeError,
            ValueError,
        ):
            return default

        if value < 1:
            return default

        return min(
            value,
            maximum,
        )


    @transaction.atomic
    def sync_markets(
        self,
        vs_currency="usd",
        page=1,
        per_page=100,
    ):
        """
        Fetch current market data and persist new snapshots.

        A separate MarketPrice row is created for every successful
        asset update so HappyWallet keeps historical snapshots.

        Returns the number of synchronized assets.
        """

        page = self._positive_integer(
            page,
            default=1,
            maximum=10000,
        )

        per_page = self._positive_integer(
            per_page,
            default=self.DEFAULT_LIMIT,
            maximum=self.MAX_LIMIT,
        )

        rows = self.provider.get_markets(
            vs_currency=vs_currency,
            page=page,
            per_page=per_page,
        )

        synchronized_count = 0

        for row in rows:
            if not isinstance(row, dict):
                continue

            coin_id = str(
                row.get("id") or ""
            ).strip()

            symbol = str(
                row.get("symbol") or ""
            ).strip()

            name = str(
                row.get("name") or ""
            ).strip()

            price_usd = self._decimal(
                row.get("current_price")
            )

            if (
                not coin_id
                or not symbol
                or not name
                or price_usd is None
            ):
                continue

            asset, _created = (
                MarketAsset.objects.update_or_create(
                    coingecko_id=coin_id,
                    defaults={
                        "symbol": symbol,
                        "name": name,
                        "image_url": str(
                            row.get("image") or ""
                        ),
                        "is_active": True,
                    },
                )
            )

            MarketPrice.objects.create(
                asset=asset,
                price_usd=price_usd,
                market_cap_usd=self._decimal(
                    row.get("market_cap")
                ),
                volume_24h_usd=self._decimal(
                    row.get("total_volume")
                ),
                price_change_24h=self._decimal(
                    row.get(
                        "price_change_percentage_24h"
                    )
                ),
                circulating_supply=self._decimal(
                    row.get("circulating_supply")
                ),
                fully_diluted_valuation_usd=(
                    self._decimal(
                        row.get(
                            "fully_diluted_valuation"
                        )
                    )
                ),
            )

            synchronized_count += 1

        return synchronized_count


    def latest_prices(
        self,
        limit=100,
    ):
        """
        Return the latest stored price for each active asset.

        The result preserves the structure expected by market/home.html:

            {
                "asset": MarketAsset,
                "price": MarketPrice,
            }
        """

        limit = self._positive_integer(
            limit,
            default=self.DEFAULT_LIMIT,
            maximum=self.MAX_LIMIT,
        )

        latest_price_queryset = (
            MarketPrice.objects
            .order_by("-captured_at")
        )

        assets = (
            MarketAsset.objects
            .filter(is_active=True)
            .prefetch_related(
                Prefetch(
                    "prices",
                    queryset=latest_price_queryset,
                    to_attr="ordered_prices",
                )
            )
            .order_by("name")[:limit]
        )

        results = []

        for asset in assets:
            if not asset.ordered_prices:
                continue

            results.append(
                {
                    "asset": asset,
                    "price": (
                        asset.ordered_prices[0]
                    ),
                }
            )

        return results


    def latest_price(
        self,
        coin_id,
    ):
        """
        Return the latest stored price for one active asset.

        Returns None when the asset or its price does not exist.
        """

        asset = (
            MarketAsset.objects
            .filter(
                coingecko_id=coin_id,
                is_active=True,
            )
            .first()
        )

        if asset is None:
            return None

        return (
            asset.prices
            .order_by("-captured_at")
            .first()
        )


    def historical_chart(
        self,
        coin_id,
        days=1,
        vs_currency="usd",
    ):
        """
        Return ordinary historical price, market-cap and volume
        series from CoinGecko.

        This method remains available for non-candlestick charts.
        """

        return self.provider.get_market_chart(
            coin_id=coin_id,
            vs_currency=vs_currency,
            days=days,
        )


    def historical_candles(
        self,
        coin_id,
        days=1,
        vs_currency="usd",
    ):
        """
        Return genuine CoinGecko OHLC candlestick data.

        Every returned candle has this structure:

            [
                timestamp,
                open,
                high,
                low,
                close,
            ]

        Candles are supplied by CoinGecko and are never fabricated
        from ordinary price points.
        """

        return self.provider.get_ohlc(
            coin_id=coin_id,
            vs_currency=vs_currency,
            days=days,
        )

    def live_markets(
        self,
        vs_currency="usd",
        page=1,
        per_page=100,
    ):
        """
        Retrieve current market information directly from CoinGecko.

        This operation is read-only. It does not modify database
        snapshots, access private keys or execute trades.
        """

        page = self._positive_integer(
            page,
            default=1,
            maximum=10000,
        )

        per_page = self._positive_integer(
            per_page,
            default=self.DEFAULT_LIMIT,
            maximum=self.MAX_LIMIT,
        )

        return self.provider.get_markets(
            vs_currency=vs_currency,
            page=page,
            per_page=per_page,
            order="market_cap_desc",
        )

