from __future__ import annotations

from decimal import Decimal, InvalidOperation

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create and validate a token definition."

    def add_arguments(self, parser):
        parser.add_argument(
            "--name",
            required=True,
            help="Token name, for example: Happy Token",
        )
        parser.add_argument(
            "--symbol",
            required=True,
            help="Token symbol, for example: HAPPY",
        )
        parser.add_argument(
            "--supply",
            required=True,
            help="Total token supply.",
        )
        parser.add_argument(
            "--decimals",
            type=int,
            default=18,
            help="Token decimal places. Default: 18.",
        )

    def handle(self, *args, **options):
        name = options["name"].strip()
        symbol = options["symbol"].strip().upper()
        supply_text = options["supply"]
        decimals = options["decimals"]

        # ------------------------------------------------------------
        # Validate name
        # ------------------------------------------------------------

        if not name:
            raise CommandError("Token name cannot be empty.")

        # ------------------------------------------------------------
        # Validate symbol
        # ------------------------------------------------------------

        if not symbol:
            raise CommandError("Token symbol cannot be empty.")

        if len(symbol) > 11:
            raise CommandError(
                "Token symbol must be 11 characters or fewer."
            )

        if not symbol.isalnum():
            raise CommandError(
                "Token symbol may contain only letters and numbers."
            )

        # ------------------------------------------------------------
        # Validate decimals
        # ------------------------------------------------------------

        if decimals < 0 or decimals > 36:
            raise CommandError(
                "Decimals must be between 0 and 36."
            )

        # ------------------------------------------------------------
        # Validate supply
        # ------------------------------------------------------------

        try:
            supply = Decimal(supply_text)
        except InvalidOperation as exc:
            raise CommandError(
                "Supply must be a valid positive number."
            ) from exc

        if supply <= 0:
            raise CommandError(
                "Supply must be greater than zero."
            )

        # ------------------------------------------------------------
        # Display validated token definition
        # ------------------------------------------------------------

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS("Token definition validated successfully.")
        )
        self.stdout.write("")
        self.stdout.write(f"Name:     {name}")
        self.stdout.write(f"Symbol:   {symbol}")
        self.stdout.write(f"Supply:   {supply}")
        self.stdout.write(f"Decimals: {decimals}")
        self.stdout.write("")
        self.stdout.write(
            self.style.WARNING(
                "Deployment has NOT been performed."
            )
        )
        self.stdout.write("")