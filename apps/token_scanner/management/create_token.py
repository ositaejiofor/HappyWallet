from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.token_scanner.services.token_factory import (
    TokenFactoryError,
    validate_token_definition,
    write_contract,
)


class Command(BaseCommand):
    help = "Validate a token definition and generate its Solidity ERC-20 contract."

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
            help="Initial token supply.",
        )
        parser.add_argument(
            "--decimals",
            type=int,
            default=18,
            help="Token decimal places. Default: 18.",
        )
        parser.add_argument(
            "--output",
            default=None,
            help=(
                "Optional Solidity output path. "
                "Defaults to apps/token_scanner/contracts/<symbol>.sol."
            ),
        )

    def handle(self, *args, **options):
        try:
            token = validate_token_definition(
                name=options["name"],
                symbol=options["symbol"],
                supply=options["supply"],
                decimals=options["decimals"],
            )
        except TokenFactoryError as exc:
            raise CommandError(str(exc)) from exc

        if options["output"]:
            output_path = Path(options["output"])
        else:
            output_path = (
                Path("apps")
                / "token_scanner"
                / "contracts"
                / f"{token.symbol}.sol"
            )

        try:
            contract_path = write_contract(
                token,
                output_path,
            )
        except OSError as exc:
            raise CommandError(
                f"Unable to write Solidity contract: {exc}"
            ) from exc

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                "Token definition validated successfully."
            )
        )
        self.stdout.write("")
        self.stdout.write(f"Name:          {token.name}")
        self.stdout.write(f"Symbol:        {token.symbol}")
        self.stdout.write(f"Supply:        {token.supply}")
        self.stdout.write(f"Decimals:      {token.decimals}")
        self.stdout.write(f"Contract:      {contract_path}")
        self.stdout.write("")
        self.stdout.write(
            self.style.WARNING(
                "Deployment has NOT been performed."
            )
        )
        self.stdout.write("")
