from django.contrib import admin

from .models import MarketAsset, MarketPrice


@admin.register(MarketAsset)
class MarketAssetAdmin(admin.ModelAdmin):
    list_display = (
        "symbol",
        "name",
        "coingecko_id",
        "chain",
        "contract_address",
        "decimals",
        "is_active",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "is_active",
        "chain",
    )

    search_fields = (
        "symbol",
        "name",
        "coingecko_id",
        "chain",
        "contract_address",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )

    ordering = (
        "name",
    )


@admin.register(MarketPrice)
class MarketPriceAdmin(admin.ModelAdmin):
    list_display = (
        "asset",
        "price_usd",
        "market_cap_usd",
        "volume_24h_usd",
        "price_change_24h",
        "captured_at",
    )

    list_filter = (
        "asset",
        "captured_at",
    )

    search_fields = (
        "asset__symbol",
        "asset__name",
        "asset__coingecko_id",
    )

    readonly_fields = (
        "captured_at",
    )

    ordering = (
        "-captured_at",
    )