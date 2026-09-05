from django.contrib import admin

from .models import Asset, BlockchainNetwork


@admin.register(BlockchainNetwork)
class BlockchainNetworkAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "symbol",
        "chain_id",
        "is_testnet",
        "is_active",
        "created_at",
    )

    list_filter = (
        "is_testnet",
        "is_active",
    )

    search_fields = (
        "name",
        "slug",
        "symbol",
        "chain_id",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    ordering = (
        "name",
    )


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = (
        "symbol",
        "name",
        "network",
        "token_standard",
        "decimals",
        "is_native",
        "is_active",
        "created_at",
    )

    list_filter = (
        "network",
        "token_standard",
        "is_native",
        "is_active",
    )

    search_fields = (
        "symbol",
        "name",
        "contract_address",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    autocomplete_fields = (
        "network",
    )

    ordering = (
        "network",
        "symbol",
    )
