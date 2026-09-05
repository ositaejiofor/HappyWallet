from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from .forms import LoginForm, RegistrationForm


LOGIN_TEMPLATE = "accounts/login.html"
REGISTER_TEMPLATE = "accounts/register.html"
ACCOUNT_TEMPLATE = "accounts/index.html"


@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Authenticate an existing HappyWallet user.

    Supports Django's ?next=/some-url/ redirect while keeping the
    authentication flow inside the accounts application.
    """
    if request.user.is_authenticated:
        return redirect("dashboard:index")

    next_url = request.GET.get("next", "").strip()

    if request.method == "POST":
        form = LoginForm(
            request=request,
            data=request.POST,
        )

        if form.is_valid():
            login(request, form.get_user())

            next_url = request.POST.get("next", "").strip() or next_url

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
    Create a new HappyWallet account and authenticate the new user.
    """
    if request.user.is_authenticated:
        return redirect("dashboard:index")

    if request.method == "POST":
        form = RegistrationForm(request.POST)

        if form.is_valid():
            user = form.save()
            login(request, user)

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
def account_home(request):
    """
    Display the authenticated user's account page.
    """
    return render(
        request,
        ACCOUNT_TEMPLATE,
        {
            "user": request.user,
            "app_name": "HappyWallet",
        },
    )


@login_required
@require_POST
def logout_view(request):
    """
    Log the current user out.

    Logout intentionally requires POST to prevent accidental logout
    through a simple GET request.
    """
    logout(request)

    messages.success(
        request,
        "You have been logged out successfully.",
    )

    return redirect("accounts:login")