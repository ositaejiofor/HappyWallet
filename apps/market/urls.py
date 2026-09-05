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
]

