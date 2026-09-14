"""
HappyWallet market views.

These views provide:

- stored market-price pages;
- individual asset pages;
- cached, read-only CoinGecko OHLC data;
- genuine candlestick chart data.

No wallet keys, signing operations or blockchain broadcasts are used.
"""

from __future__ import annotations

from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import (
    get_object_or_404,
    render,
)
from django.views.decorators.http import require_GET

from .models import MarketAsset
from .services.price_service import MarketPriceService
from .services.providers.coingecko import CoinGeckoError


CHART_RANGES = {
    1,
    7,
    14,
    30,
    90,
    180,
    365,
}

CHART_CACHE_SECONDS = 60
MARKET_LIVE_CACHE_SECONDS = 60


def market_home(request):
    """
    Display the latest stored price for each active asset.
    """

    service = MarketPriceService()

    assets = service.latest_prices(
        limit=100,
    )

    return render(
        request,
        "market/home.html",
        {
            "assets": assets,
        },
    )


def asset_detail(
    request,
    coin_id,
):
    """
    Display one market asset and its latest stored price.
    """

    asset = get_object_or_404(
        MarketAsset,
        coingecko_id=coin_id,
        is_active=True,
    )

    latest_price = (
        asset.prices
        .order_by("-captured_at")
        .first()
    )

    return render(
        request,
        "market/asset_detail.html",
        {
            "asset": asset,
            "latest_price": latest_price,
            "chart_ranges": sorted(
                CHART_RANGES
            ),
        },
    )


def _normalize_candles(values):
    """
    Validate CoinGecko OHLC candles before returning them.

    Expected provider format:

        [
            timestamp,
            open,
            high,
            low,
            close,
        ]
    """

    normalized = []

    if not isinstance(values, list):
        return normalized

    for value in values:
        if (
            not isinstance(value, list)
            or len(value) < 5
        ):
            continue

        try:
            timestamp = int(value[0])
            open_price = float(value[1])
            high_price = float(value[2])
            low_price = float(value[3])
            close_price = float(value[4])

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):
            continue


        if timestamp < 0:
            continue

        if high_price < low_price:
            continue

        if high_price < max(
            open_price,
            close_price,
        ):
            continue

        if low_price > min(
            open_price,
            close_price,
        ):
            continue


        normalized.append(
            [
                timestamp,
                open_price,
                high_price,
                low_price,
                close_price,
            ]
        )

    return normalized


@require_GET
def asset_chart_data(
    request,
    coin_id,
):
    """
    Return genuine OHLC candlestick data for one active asset.

    Query parameter:

        days=1|7|14|30|90|180|365

    Successful response:

        {
            "coin_id": "bitcoin",
            "symbol": "BTC",
            "currency": "USD",
            "days": 1,
            "candles": [
                [
                    timestamp,
                    open,
                    high,
                    low,
                    close
                ]
            ]
        }
    """

    asset = get_object_or_404(
        MarketAsset,
        coingecko_id=coin_id,
        is_active=True,
    )


    try:
        days = int(
            request.GET.get(
                "days",
                "1",
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        return JsonResponse(
            {
                "error": (
                    "days must be an integer."
                ),
            },
            status=400,
        )


    if days not in CHART_RANGES:
        allowed_ranges = ", ".join(
            str(value)
            for value in sorted(
                CHART_RANGES
            )
        )

        return JsonResponse(
            {
                "error": (
                    "Unsupported chart range. "
                    f"Allowed days: {allowed_ranges}."
                ),
            },
            status=400,
        )


    cache_key = (
        "market-candles:v1:"
        f"{asset.coingecko_id}:"
        f"usd:{days}"
    )

    payload = cache.get(
        cache_key
    )


    if payload is None:
        service = MarketPriceService()

        try:
            raw_candles = (
                service.historical_candles(
                    coin_id=(
                        asset.coingecko_id
                    ),
                    days=days,
                    vs_currency="usd",
                )
            )

        except CoinGeckoError:
            return JsonResponse(
                {
                    "error": (
                        "Live candlestick data is "
                        "temporarily unavailable."
                    ),
                },
                status=502,
            )


        candles = _normalize_candles(
            raw_candles
        )

        if not candles:
            return JsonResponse(
                {
                    "error": (
                        "The market provider returned "
                        "no valid OHLC candles."
                    ),
                },
                status=502,
            )


        payload = {
            "coin_id": (
                asset.coingecko_id
            ),
            "symbol": (
                asset.symbol.upper()
            ),
            "currency": "USD",
            "days": days,
            "candles": candles,
        }

        cache.set(
            cache_key,
            payload,
            CHART_CACHE_SECONDS,
        )


    return JsonResponse(
        payload,
        status=200,
    )

@require_GET
def market_live_data(request):
    """
    Return current CoinGecko market information for the homepage.

    The response is cached to reduce provider requests and avoid
    exceeding CoinGecko rate limits.
    """

    cache_key = "market-live:v1:usd:1:100"

    payload = cache.get(cache_key)

    if payload is None:
        service = MarketPriceService()

        try:
            rows = service.live_markets(
                vs_currency="usd",
                page=1,
                per_page=100,
            )

        except CoinGeckoError:
            return JsonResponse(
                {
                    "error": (
                        "Live market information is "
                        "temporarily unavailable."
                    ),
                },
                status=502,
            )

        assets = []

        for row in rows:
            if not isinstance(row, dict):
                continue

            coin_id = str(
                row.get("id") or ""
            ).strip()

            symbol = str(
                row.get("symbol") or ""
            ).strip().upper()

            name = str(
                row.get("name") or ""
            ).strip()

            if not coin_id or not symbol or not name:
                continue

            assets.append(
                {
                    "coin_id": coin_id,
                    "symbol": symbol,
                    "name": name,
                    "image_url": str(
                        row.get("image") or ""
                    ),
                    "price_usd": row.get(
                        "current_price"
                    ),
                    "market_cap_usd": row.get(
                        "market_cap"
                    ),
                    "volume_24h_usd": row.get(
                        "total_volume"
                    ),
                    "price_change_24h": row.get(
                        "price_change_percentage_24h"
                    ),
                    "market_cap_rank": row.get(
                        "market_cap_rank"
                    ),
                    "last_updated": row.get(
                        "last_updated"
                    ),
                }
            )

        payload = {
            "currency": "USD",
            "assets": assets,
        }

        cache.set(
            cache_key,
            payload,
            MARKET_LIVE_CACHE_SECONDS,
        )

    return JsonResponse(
        payload,
        status=200,
    )

