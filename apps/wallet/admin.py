# apps/wallet/admin.py

from django.contrib import admin

from .models import Wallet, WalletAddress


# ============================================================
# WALLET ADMIN
# ============================================================


@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    """
    Django admin configuration for Wallet.

    Private keys and recovery phrases are intentionally not
    represented by this model or exposed through the admin.
    """

    list_display = (
        "name",
        "user",
        "network",
        "address",
        "status",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "status",
        "network",
        "created_at",
    )

    search_fields = (
        "name",
        "address",
        "user__email",
        "user__username",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    autocomplete_fields = (
        "user",
        "network",
    )

    ordering = (
        "-created_at",
    )

    list_per_page = 25


# ============================================================
# WALLET ADDRESS ADMIN
# ============================================================


@admin.register(WalletAddress)
class WalletAddressAdmin(admin.ModelAdmin):
    """
    Django admin configuration for public wallet addresses.

    WalletAddress contains public blockchain information only.
    """

    list_display = (
        "wallet",
        "network",
        "address",
        "derivation_path",
        "is_active",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "network",
        "is_active",
        "created_at",
    )

    search_fields = (
        "address",
        "derivation_path",
        "wallet__name",
        "wallet__address",
        "wallet__user__email",
        "wallet__user__username",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    autocomplete_fields = (
        "wallet",
        "network",
    )

    ordering = (
        "-created_at",
    )

    list_per_page = 25