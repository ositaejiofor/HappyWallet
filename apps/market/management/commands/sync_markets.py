from django.core.management.base import BaseCommand, CommandError

from apps.market.services.price_service import MarketPriceService
from apps.market.services.providers.coingecko import CoinGeckoError


class Command(BaseCommand):
    help = "Synchronize cryptocurrency market data from the configured provider."

    def add_arguments(self, parser):
        parser.add_argument(
            "--vs-currency",
            default="usd",
            help="Quote currency used for market prices.",
        )
        parser.add_argument(
            "--page",
            type=int,
            default=1,
            help="Provider page number.",
        )
        parser.add_argument(
            "--per-page",
            type=int,
            default=100,
            help="Number of assets to request.",
        )

    def handle(self, *args, **options):
        vs_currency = options["vs_currency"]
        page = options["page"]
        per_page = options["per_page"]

        if page < 1:
            raise CommandError("--page must be at least 1.")

        if per_page < 1 or per_page > 250:
            raise CommandError("--per-page must be between 1 and 250.")

        service = MarketPriceService()

        self.stdout.write(
            f"Synchronizing market data "
            f"(currency={vs_currency}, page={page}, per_page={per_page})..."
        )

        try:
            count = service.sync_markets(
                vs_currency=vs_currency,
                page=page,
                per_page=per_page,
            )
        except CoinGeckoError as exc:
            raise CommandError(str(exc)) from exc
        except Exception as exc:
            raise CommandError(
                f"Market synchronization failed: {exc}"
            ) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Market synchronization complete: {count} assets synchronized."
            )
        )
