from django.contrib import admin

from .models import LedgerAccount, LedgerEntry


@admin.register(LedgerAccount)
class LedgerAccountAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "asset",
        "account_type",
        "wallet",
        "user",
        "is_active",
        "created_at",
    )

    list_filter = (
        "account_type",
        "asset",
        "is_active",
    )

    search_fields = (
        "name",
        "asset",
        "wallet__name",
        "wallet__id",
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
        "wallet",
    )

    ordering = (
        "-created_at",
    )


@admin.register(LedgerEntry)
class LedgerEntryAdmin(admin.ModelAdmin):
    list_display = (
        "account",
        "entry_type",
        "amount",
        "reference",
        "created_at",
    )

    list_filter = (
        "entry_type",
        "created_at",
    )

    search_fields = (
        "reference",
        "description",
        "account__name",
        "account__asset",
    )

    readonly_fields = (
        "id",
        "account",
        "entry_type",
        "amount",
        "reference",
        "description",
        "created_at",
    )

    autocomplete_fields = (
        "account",
    )

    ordering = (
        "-created_at",
    )

    date_hierarchy = "created_at"