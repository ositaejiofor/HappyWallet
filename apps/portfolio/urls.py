# apps/portfolio/urls.py

from __future__ import annotations

from django.urls import path

from . import views


# ============================================================================
# APPLICATION NAMESPACE
# ============================================================================

app_name = "portfolio"


# ============================================================================
# URL PATTERNS
# ============================================================================

urlpatterns = [
    path(
        "",
        views.portfolio,
        name="index",
    ),
]