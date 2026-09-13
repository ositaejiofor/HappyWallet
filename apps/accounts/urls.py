# apps/accounts/urls.py

from django.urls import path

from . import views


app_name = "accounts"


urlpatterns = [
    path(
        "",
        views.account_redirect,
        name="index",
    ),
    path(
        "login/",
        views.login_view,
        name="login",
    ),
    path(
        "register/",
        views.register_view,
        name="register",
    ),
    path(
        "account/",
        views.account_home,
        name="account",
    ),
    path(
        "password/change/",
        views.password_change_view,
        name="password_change",
    ),
    path(
        "logout/",
        views.logout_view,
        name="logout",
    ),
]