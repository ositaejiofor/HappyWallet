from django.contrib import admin

from .models import (
    Order,
    Trade,
    TradingAccount,
    TradingBalance,
    TradingPair,
)


@admin.register(TradingAccount)
class TradingAccountAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "name",
        "mode",
        "is_active",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "mode",
        "is_active",
    )

    search_fields = (
        "user__username",
        "user__email",
        "name",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )


@admin.register(TradingBalance)
class TradingBalanceAdmin(admin.ModelAdmin):
    list_display = (
        "account",
        "asset",
        "available",
        "locked",
        "total",
        "updated_at",
    )

    list_filter = (
        "asset",
    )

    search_fields = (
        "account__user__username",
        "account__user__email",
        "asset__symbol",
        "asset__name",
    )

    readonly_fields = (
        "total",
        "updated_at",
    )


@admin.register(TradingPair)
class TradingPairAdmin(admin.ModelAdmin):
    list_display = (
        "symbol",
        "base_asset",
        "quote_asset",
        "is_active",
        "min_order_quantity",
        "max_order_quantity",
        "price_precision",
        "quantity_precision",
    )

    list_filter = (
        "is_active",
    )

    search_fields = (
        "symbol",
        "base_asset__symbol",
        "base_asset__name",
        "quote_asset__symbol",
        "quote_asset__name",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "client_order_id",
        "account",
        "pair",
        "side",
        "order_type",
        "quantity",
        "filled_quantity",
        "average_fill_price",
        "status",
        "created_at",
    )

    list_filter = (
        "side",
        "order_type",
        "status",
    )

    search_fields = (
        "client_order_id",
        "account__user__username",
        "account__user__email",
        "pair__symbol",
    )

    readonly_fields = (
        "client_order_id",
        "created_at",
        "updated_at",
    )


@admin.register(Trade)
class TradeAdmin(admin.ModelAdmin):
    list_display = (
        "execution_id",
        "order",
        "quantity",
        "price",
        "fee",
        "fee_asset",
        "executed_at",
        "notional_value",
    )

    list_filter = (
        "fee_asset",
    )

    search_fields = (
        "execution_id",
        "order__client_order_id",
        "order__account__user__username",
        "order__account__user__email",
        "order__pair__symbol",
    )

    readonly_fields = (
        "execution_id",
        "executed_at",
        "notional_value",
    )
    
    
    