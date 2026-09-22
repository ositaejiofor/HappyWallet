"""
URL routes for the HappyWallet trading application.
"""

from django.urls import path

from . import views


app_name = "trading"


urlpatterns = [
    # Trading dashboard
    path(
        "",
        views.trading_home,
        name="home",
    ),

    # Kraken public market data
    path(
        "api/kraken/prices/",
        views.kraken_live_prices,
        name="kraken_live_prices",
    ),

    # Order listing and creation
    path(
        "orders/",
        views.order_list,
        name="order_list",
    ),
    path(
        "orders/create/",
        views.create_order,
        name="create_order",
    ),

    # Individual order
    path(
        "orders/<int:order_id>/",
        views.order_detail,
        name="order_detail",
    ),
    path(
        "orders/<int:order_id>/cancel/",
        views.cancel_order,
        name="cancel_order",
    ),

    # Paper execution
    path(
        "orders/<int:order_id>/execute/",
        views.execute_paper_order,
        name="execute_paper_order",
    ),

    # Guarded Kraken live execution
    path(
        "orders/<int:order_id>/execute-live/",
        views.execute_live_order,
        name="execute_live_order",
    ),
    path(
        "orders/<int:order_id>/reconcile/",
        views.reconcile_live_order,
        name="reconcile_live_order",
    ),
    path(
        "orders/<int:order_id>/cancel-live/",
        views.cancel_live_order,
        name="cancel_live_order",
    ),

        # Private read-only Kraken account dashboard
    path(
        "kraken/account/",
        views.kraken_account_dashboard,
        name="kraken_account",
    ),
]