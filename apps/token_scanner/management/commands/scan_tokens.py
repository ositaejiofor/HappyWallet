from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.blockchain.services.network import blockchain_network_service
from apps.token_scanner.services.discovery import (
    EthereumTokenDiscovery,
    TokenDiscoveryError,
)
from apps.token_scanner.services.persistence import TokenScanPersistence
from apps.token_scanner.services.scanner import EVMTokenScanner


class Command(BaseCommand):
    help = (
        "Discover newly created ERC-20-like contracts on Ethereum Mainnet, "
        "scan their on-chain state, and persist historical observations."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--from-block",
            type=int,
            default=None,
            help="First Ethereum block to inspect.",
        )
        parser.add_argument(
            "--to-block",
            type=int,
            default=None,
            help="Last Ethereum block to inspect.",
        )
        parser.add_argument(
            "--blocks",
            type=int,
            default=20,
            help=(
                "Number of recent blocks to inspect when --from-block and "
                "--to-block are not both supplied. Maximum is 100."
            ),
        )
        parser.add_argument(
            "--max-tokens",
            type=int,
            default=25,
            help="Maximum number of discovered token contracts to scan.",
        )
        parser.add_argument(
            "--complete-holder-history",
            action="store_true",
            help=(
                "Mark holder analysis as a complete-history request. "
                "The analyzer may still be bounded by its configured limits."
            ),
        )

    def handle(self, *args: Any, **options: Any):
        try:
            network = blockchain_network_service.get_by_slug(
                slug="ethereum-mainnet"
            )
        except Exception as exc:
            raise CommandError(
                "Unable to resolve Ethereum Mainnet from the blockchain "
                "network service."
            ) from exc

        if network is None:
            raise CommandError(
                "Ethereum Mainnet is not configured in HappyWallet."
            )

        rpc_url = self._get_rpc_url(network)

        if not rpc_url:
            raise CommandError(
                "Ethereum Mainnet has no configured RPC URL."
            )

        max_tokens = options["max_tokens"]

        if max_tokens < 1:
            raise CommandError("--max-tokens must be at least 1.")

        start_block, end_block = self._resolve_block_range(
            rpc_url=rpc_url,
            from_block=options["from_block"],
            to_block=options["to_block"],
            blocks=options["blocks"],
        )

        discovery = EthereumTokenDiscovery(
            rpc_url=rpc_url,
        )

        scanner = EVMTokenScanner(
            rpc_url=rpc_url,
        )

        persistence = TokenScanPersistence()

        self.stdout.write(
            self.style.NOTICE(
                "HappyWallet Token Scanner"
            )
        )
        self.stdout.write(
            f"Network: Ethereum Mainnet (chain ID {network.chain_id})"
        )
        self.stdout.write(
            f"Block range: {start_block} -> {end_block}"
        )

        try:
            discovered = discovery.discover(
                from_block=start_block,
                to_block=end_block,
            )
        except TokenDiscoveryError as exc:
            raise CommandError(
                f"Token discovery failed: {exc}"
            ) from exc
        except Exception as exc:
            raise CommandError(
                f"Unexpected token discovery failure: {exc}"
            ) from exc

        self.stdout.write(
            f"Transactions examined: {discovered.transactions_examined}"
        )
        self.stdout.write(
            f"Contracts examined: {discovered.contracts_examined}"
        )
        self.stdout.write(
            f"ERC-20-like candidates: {discovered.candidate_count}"
        )

        if discovered.warnings:
            self.stdout.write(
                self.style.WARNING(
                    "Discovery warnings:"
                )
            )
            for warning in discovered.warnings:
                self.stdout.write(f"  - {warning}")

        if not discovered.candidates:
            self.stdout.write(
                self.style.SUCCESS(
                    "No ERC-20-like token candidates were discovered "
                    "in this block range."
                )
            )
            return

        candidates = discovered.candidates[:max_tokens]

        if len(discovered.candidates) > max_tokens:
            self.stdout.write(
                self.style.WARNING(
                    f"Limiting scan to {max_tokens} of "
                    f"{discovered.candidate_count} candidates."
                )
            )

        persisted_count = 0
        alert_count = 0
        failed_count = 0

        for candidate in candidates:
            self.stdout.write("")
            self.stdout.write(
                f"Scanning {candidate.address}"
            )

            if candidate.name or candidate.symbol:
                self.stdout.write(
                    f"  Token: "
                    f"{candidate.name or '(unknown name)'} "
                    f"({candidate.symbol or '(unknown symbol)'})"
                )

            try:
                result = scanner.scan(
                    candidate.address,
                    pool_addresses=(),
                    from_block=start_block,
                    to_block=end_block,
                    decimals=candidate.decimals,
                    contract_verified=candidate.contract.verified,
                    complete_holder_history=options[
                        "complete_holder_history"
                    ],
                )

                persistence_result = persistence.persist(
                    result,
                )

                persisted_count += 1
                alert_count += len(persistence_result.alerts)

                self.stdout.write(
                    self.style.SUCCESS(
                        f"  Persisted scan: "
                        f"{persistence_result.token.symbol or candidate.address}"
                    )
                )
                self.stdout.write(
                    f"  Risk score: {result.risk.score}/100 "
                    f"({result.risk.rating})"
                )
                self.stdout.write(
                    f"  Holders observed: "
                    f"{result.holders.holder_count}"
                )
                self.stdout.write(
                    f"  Buy/Sell events: "
                    f"{result.demand.buy_count}/"
                    f"{result.demand.sell_count}"
                )
                self.stdout.write(
                    f"  Liquidity pools observed: "
                    f"{result.liquidity.liquidity_pool_count}"
                )

                if result.warnings:
                    self.stdout.write(
                        self.style.WARNING(
                            "  Scan warnings:"
                        )
                    )
                    for warning in result.warnings:
                        self.stdout.write(
                            f"    - {warning}"
                        )

            except Exception as exc:
                failed_count += 1
                self.stdout.write(
                    self.style.ERROR(
                        f"  Scan failed for {candidate.address}: {exc}"
                    )
                )

        self.stdout.write("")
        self.stdout.write(
            self.style.NOTICE(
                "Scan complete"
            )
        )
        self.stdout.write(
            f"Candidates discovered: {discovered.candidate_count}"
        )
        self.stdout.write(
            f"Candidates scanned: {len(candidates)}"
        )
        self.stdout.write(
            f"Scans persisted: {persisted_count}"
        )
        self.stdout.write(
            f"Alerts created: {alert_count}"
        )
        self.stdout.write(
            f"Failed scans: {failed_count}"
        )

        if failed_count:
            self.stdout.write(
                self.style.WARNING(
                    "One or more candidates could not be scanned."
                )
            )

    @staticmethod
    def _get_rpc_url(network):
        """
        Resolve the configured RPC URL without hard-coding credentials.

        HappyWallet's blockchain network object may expose the endpoint
        through different attributes depending on the current model/service
        implementation, so inspect the configured public endpoint fields.
        """

        for attribute in (
            "rpc_url",
            "http_rpc_url",
            "endpoint",
            "url",
        ):
            value = getattr(network, attribute, None)

            if value:
                return str(value).strip()

        return None

    @staticmethod
    def _resolve_block_range(
        *,
        rpc_url: str,
        from_block: int | None,
        to_block: int | None,
        blocks: int,
    ) -> tuple[int, int]:
        discovery = EthereumTokenDiscovery(
            rpc_url=rpc_url,
        )

        latest = discovery.latest_block()

        if from_block is not None and from_block < 0:
            raise CommandError(
                "--from-block must be non-negative."
            )

        if to_block is not None and to_block < 0:
            raise CommandError(
                "--to-block must be non-negative."
            )

        if from_block is not None and to_block is not None:
            start = from_block
            end = to_block
        elif from_block is not None:
            start = from_block
            end = latest
        elif to_block is not None:
            end = min(to_block, latest)
            start = max(0, end - blocks + 1)
        else:
            if blocks < 1:
                raise CommandError(
                    "--blocks must be at least 1."
                )

            if blocks > 100:
                raise CommandError(
                    "--blocks cannot exceed 100."
                )

            end = latest
            start = max(0, end - blocks + 1)

        if end > latest:
            raise CommandError(
                f"--to-block cannot exceed the latest Ethereum block "
                f"({latest})."
            )

        if start > end:
            raise CommandError(
                "The starting block cannot be greater than the ending block."
            )

        if end - start + 1 > 100:
            raise CommandError(
                "The requested discovery range exceeds the scanner's "
                "100-block safety limit."
            )

        return start, end
