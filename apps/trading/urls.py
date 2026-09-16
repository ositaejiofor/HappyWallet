from django.urls import path

from . import views


app_name = "trading"


urlpatterns = [
    path(
        "",
        views.trading_home,
        name="home",
    ),

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

    path(
        "orders/<int:order_id>/execute/",
        views.execute_paper_order,
        name="execute_paper_order",
    ),

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
]
