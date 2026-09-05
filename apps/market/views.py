from django.shortcuts import get_object_or_404, render

from .models import MarketAsset
from .services.price_service import MarketPriceService


def market_home(request):
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


def asset_detail(request, coin_id):
    service = MarketPriceService()

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
        },
    )