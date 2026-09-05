from django.contrib import admin

from .models import Transaction


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "wallet",
        "network",
        "transaction_type",
        "asset",
        "amount",
        "status",
        "transaction_hash",
        "created_at",
    )

    list_filter = (
        "network",
        "transaction_type",
        "status",
        "asset",
        "created_at",
    )

    search_fields = (
        "id",
        "user__email",
        "wallet__name",
        "sender",
        "recipient",
        "transaction_hash",
        "payload_hash",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "signed_at",
        "broadcast_at",
        "confirmed_at",
    )

    autocomplete_fields = (
        "user",
        "wallet",
        "network",
    )

    ordering = (
        "-created_at",
    )