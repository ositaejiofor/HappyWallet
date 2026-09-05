from django.contrib import admin

from .models import Token


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = (
        "symbol",
        "name",
        "chain",
        "contract_address",
        "liquidity_usd",
        "volume_24h_usd",
        "holder_count",
        "risk_score",
        "first_seen_at",
    )

    list_filter = (
        "chain",
        "contract_verified",
        "liquidity_locked",
        "blacklist_detected",
        "unlimited_mint_detected",
    )

    search_fields = (
        "name",
        "symbol",
        "contract_address",
    )

    ordering = (
        "-first_seen_at",
    )