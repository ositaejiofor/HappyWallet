from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.security.password_policy import PasswordPolicyService


@login_required
def home(request):
    """
    Display the authenticated user's security status.

    This view intentionally exposes security state only.
    It must never expose passwords, private keys, mnemonics,
    decrypted vault contents, or encryption keys.
    """

    context = {
        "security": {
            "authentication": {
                "status": "Protected",
                "description": "Your account requires authenticated access.",
            },
            "password": {
                "status": "Protected",
                "description": "Your password is stored using secure password hashing.",
            },
            "password_policy": {
                "status": "Enforced",
                "description": "Password policy validation is enabled.",
            },
            "encryption": {
                "status": "Enabled",
                "description": "Wallet secret material is protected by the security layer.",
            },
            "audit": {
                "status": "Enabled",
                "description": "Security events can be recorded through the audit system.",
            },
            "rate_limiting": {
                "status": "Enabled",
                "description": "Authentication/security rate limiting is available.",
            },
        },
        "password_policy": PasswordPolicyService,
    }

    return render(
        request,
        "security/home.html",
        context,
    )