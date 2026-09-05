# apps/transaction/urls.py

from __future__ import annotations

from django.urls import path

from . import views


# ============================================================================
# APPLICATION NAMESPACE
# ============================================================================

app_name = "transaction"


# ============================================================================
# URL PATTERNS
# ============================================================================

urlpatterns = [
    path(
        "",
        views.transaction_list,
        name="index",
    ),
]