from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.db import transaction

from apps.market.models import MarketAsset, MarketPrice

from .coingecko import (
    CoinGeckoError,
    CoinGeckoProvider,
)


class MarketPriceService:
    """
    Application service for importing and retrieving market prices.
    """

    def __init__(self, provider=None):
        if provider is not None:
            self.provider = provider
        else:
            api_key = getattr(
                settings,
                "COINGECKO_API_KEY",
                "",
            )

            self.provider = CoinGeckoProvider(
                api_key=api_key,
            )

    @staticmethod
    def _decimal(value):
        if value is None:
            return None

        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError):
            return None

    @transaction.atomic
    def sync_markets(
        self,
        vs_currency="usd",
        page=1,
        per_page=100,
    ):
        """
        Fetch market data and persist it locally.

        Returns the number of assets synchronized.
        """

        rows = self.provider.get_markets(
            vs_currency=vs_currency,
            page=page,
            per_page=per_page,
        )

        count = 0

        for row in rows:
            coin_id = row.get("id")

            if not coin_id:
                continue

            asset, _ = MarketAsset.objects.update_or_create(
                coingecko_id=coin_id,
                defaults={
                    "symbol": row.get("symbol", ""),
                    "name": row.get("name", ""),
                    "image_url": row.get("image", ""),
                    "is_active": True,
                },
            )

            MarketPrice.objects.create(
                asset=asset,
                price_usd=self._decimal(
                    row.get("current_price")
                ) or Decimal("0"),
                market_cap_usd=self._decimal(
                    row.get("market_cap")
                ),
                volume_24h_usd=self._decimal(
                    row.get("total_volume")
                ),
                price_change_24h=self._decimal(
                    row.get("price_change_percentage_24h")
                ),
                circulating_supply=self._decimal(
                    row.get("circulating_supply")
                ),
                fully_diluted_valuation_usd=self._decimal(
                    row.get("fully_diluted_valuation")
                ),
            )

            count += 1

        return count

    def latest_prices(self, limit=100):
        """
        Return the latest known price for each active asset.
        """

        assets = MarketAsset.objects.filter(
            is_active=True,
        ).prefetch_related("prices")

        results = []

        for asset in assets[:limit]:
            price = (
                asset.prices
                .order_by("-captured_at")
                .first()
            )

            if price is None:
                continue

            results.append(
                {
                    "asset": asset,
                    "price": price,
                }
            )

        return results

    def historical_chart(
        self,
        coin_id,
        days=1,
        vs_currency="usd",
    ):
        return self.provider.get_market_chart(
            coin_id=coin_id,
            vs_currency=vs_currency,
            days=days,
        )