from django.shortcuts import render

from .models import Token


def index(request):
    tokens = (
        Token.objects
        .order_by("-first_seen_at")[:100]
    )

    return render(
        request,
        "token_scanner/index.html",
        {
            "tokens": tokens,
        },
    )