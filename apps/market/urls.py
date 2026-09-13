from django.urls import path

from . import views


app_name = "market"


urlpatterns = [
    path(
        "",
        views.market_home,
        name="home",
    ),

    path(
        "asset/<str:coin_id>/",
        views.asset_detail,
        name="asset_detail",
    ),

    path(
        "api/live/",
        views.market_live_data,
        name="live_data",
    ),

    path(
        "api/assets/<str:coin_id>/chart/",
        views.asset_chart_data,
        name="asset_chart_data",
    ),
]