# apps/accounts/views.py

"""
HappyWallet account views.

Handles account registration, authentication, profile updates,
password changes, and secure session logout.
"""

from django.contrib import messages
from django.contrib.auth import (
    login,
    logout,
    update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import (
    require_http_methods,
    require_POST,
)

from .forms import (
    AccountPasswordChangeForm,
    AccountUpdateForm,
    LoginForm,
    RegistrationForm,
)


LOGIN_TEMPLATE = "accounts/login.html"
REGISTER_TEMPLATE = "accounts/register.html"
ACCOUNT_TEMPLATE = "accounts/index.html"
PASSWORD_CHANGE_TEMPLATE = "accounts/password_change.html"


def _safe_next_url(request):
    """
    Return a validated local redirect from the `next` parameter.

    External redirect targets are rejected to prevent open-redirect
    vulnerabilities.
    """
    next_url = (
        request.POST.get("next")
        or request.GET.get("next")
        or ""
    ).strip()

    if not next_url:
        return ""

    if not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return ""

    return next_url


def account_redirect(request):
    """
    Route /accounts/ according to authentication status.
    """
    if request.user.is_authenticated:
        return redirect("accounts:account")

    return redirect("accounts:login")


@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Authenticate an existing HappyWallet user.
    """
    if request.user.is_authenticated:
        return redirect("accounts:account")

    next_url = _safe_next_url(request)

    if request.method == "POST":
        form = LoginForm(
            request=request,
            data=request.POST,
        )

        if form.is_valid():
            login(
                request,
                form.get_user(),
            )

            messages.success(
                request,
                "You have signed in successfully.",
            )

            if next_url:
                return redirect(next_url)

            return redirect("dashboard:index")
    else:
        form = LoginForm(request=request)

    return render(
        request,
        LOGIN_TEMPLATE,
        {
            "form": form,
            "next": next_url,
        },
    )


@require_http_methods(["GET", "POST"])
def register_view(request):
    """
    Create and authenticate a new HappyWallet user.
    """
    if request.user.is_authenticated:
        return redirect("accounts:account")

    if request.method == "POST":
        form = RegistrationForm(request.POST)

        if form.is_valid():
            user = form.save()

            login(
                request,
                user,
            )

            messages.success(
                request,
                "Your HappyWallet account has been created successfully.",
            )

            return redirect("dashboard:index")
    else:
        form = RegistrationForm()

    return render(
        request,
        REGISTER_TEMPLATE,
        {
            "form": form,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def account_home(request):
    """
    Display and update the authenticated user's account information.
    """
    if request.method == "POST":
        form = AccountUpdateForm(
            data=request.POST,
            instance=request.user,
        )

        if form.is_valid():
            form.save()

            messages.success(
                request,
                "Your account information has been updated successfully.",
            )

            return redirect("accounts:account")
    else:
        form = AccountUpdateForm(
            instance=request.user,
        )

    return render(
        request,
        ACCOUNT_TEMPLATE,
        {
            "form": form,
            "user": request.user,
            "app_name": "HappyWallet",
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def password_change_view(request):
    """
    Change the authenticated user's password securely.
    """
    if request.method == "POST":
        form = AccountPasswordChangeForm(
            user=request.user,
            data=request.POST,
        )

        if form.is_valid():
            user = form.save()

            # Password changes normally invalidate the current session.
            # Updating the session hash keeps the user securely signed in.
            update_session_auth_hash(
                request,
                user,
            )

            messages.success(
                request,
                "Your password has been changed successfully.",
            )

            return redirect("accounts:account")
    else:
        form = AccountPasswordChangeForm(
            user=request.user,
        )

    return render(
        request,
        PASSWORD_CHANGE_TEMPLATE,
        {
            "form": form,
            "user": request.user,
            "app_name": "HappyWallet",
        },
    )


@login_required
@require_POST
def logout_view(request):
    """
    End the authenticated user's session.

    Logout requires POST to protect against accidental or malicious
    logout requests made through ordinary links.
    """
    logout(request)

    messages.success(
        request,
        "You have been logged out successfully.",
    )

    return redirect("accounts:login")