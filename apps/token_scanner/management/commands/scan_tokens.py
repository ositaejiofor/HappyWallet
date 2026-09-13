from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.blockchain.services.network import blockchain_network_service
from apps.token_scanner.services.dex_config import ETHEREUM_DEX_FACTORIES
from apps.token_scanner.services.persistence import TokenScanPersistence
from apps.token_scanner.services.scanner import (
    EVMTokenScanner,
    TokenDiscoveryScanError,
)


class Command(BaseCommand):
    help = (
        "Discover real Ethereum DEX liquidity pools, analyze the tokens "
        "behind those pools, and persist read-only scanner observations."
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
                "Request complete holder-history analysis where supported. "
                "The analyzer may still apply configured safety limits."
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

        scanner = EVMTokenScanner(
            rpc_url=rpc_url,
            factories=ETHEREUM_DEX_FACTORIES,
            dex_max_blocks=100,
        )

        persistence = TokenScanPersistence()

        self.stdout.write(
            self.style.NOTICE(
                "HappyWallet Token Scanner"
            )
        )
        self.stdout.write(
            "Mode: READ-ONLY"
        )
        self.stdout.write(
            "Network: Ethereum Mainnet "
            f"(chain ID {network.chain_id})"
        )
        self.stdout.write(
            f"DEX factories: {len(ETHEREUM_DEX_FACTORIES)}"
        )
        for factory in ETHEREUM_DEX_FACTORIES:
            self.stdout.write(
                f"  - {factory.name}: {factory.address}"
            )

        self.stdout.write(
            f"Block range: {start_block} -> {end_block}"
        )
        self.stdout.write(
            f"Maximum tokens: {max_tokens}"
        )

        try:
            discovery_result = scanner.discover_and_scan(
                from_block=start_block,
                to_block=end_block,
                max_tokens=max_tokens,
                complete_holder_history=options[
                    "complete_holder_history"
                ],
            )
        except TokenDiscoveryScanError as exc:
            raise CommandError(
                f"DEX token discovery/scan failed: {exc}"
            ) from exc
        except Exception as exc:
            raise CommandError(
                f"Unexpected DEX token scanner failure: {exc}"
            ) from exc

        discovery = discovery_result.discovery

        self.stdout.write("")
        self.stdout.write(
            self.style.NOTICE(
                "DEX discovery result"
            )
        )
        self.stdout.write(
            f"Factories examined: {discovery.factories_examined}"
        )
        self.stdout.write(
            f"Pool logs examined: {discovery.logs_examined}"
        )
        self.stdout.write(
            f"Pools discovered: {discovery.pool_count}"
        )
        self.stdout.write(
            f"Token contracts discovered: "
            f"{discovery_result.token_count}"
        )

        if discovery.complete:
            self.stdout.write(
                self.style.SUCCESS(
                    "DEX discovery completed within configured limits."
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    "DEX discovery was incomplete or reached a configured "
                    "safety limit."
                )
            )

        if discovery.warnings:
            self.stdout.write(
                self.style.WARNING(
                    "DEX discovery warnings:"
                )
            )
            for warning in discovery.warnings:
                self.stdout.write(
                    f"  - {warning}"
                )

        if discovery_result.warnings:
            self.stdout.write(
                self.style.WARNING(
                    "Scanner warnings:"
                )
            )
            for warning in discovery_result.warnings:
                self.stdout.write(
                    f"  - {warning}"
                )

        if not discovery_result.tokens:
            self.stdout.write("")
            self.stdout.write(
                self.style.SUCCESS(
                    "No real token contracts were discovered from "
                    "DEX pool-creation events in this block range."
                )
            )
            return

        persisted_count = 0
        alert_count = 0
        failed_count = 0

        for discovered_token in discovery_result.tokens:
            result = discovered_token.scan
            address = discovered_token.token_address

            self.stdout.write("")
            self.stdout.write(
                f"Token: {result.name or '(unknown name)'} "
                f"({result.symbol or '(unknown symbol)'})"
            )
            self.stdout.write(
                f"Address: {address}"
            )
            self.stdout.write(
                f"DEX pools: {len(discovered_token.pool_addresses)}"
            )

            try:
                persistence_result = persistence.persist(
                    result,
                )

                persisted_count += 1
                alert_count += len(
                    persistence_result.alerts
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        "  Persisted real blockchain observation."
                    )
                )
                self.stdout.write(
                    f"  Risk score: "
                    f"{result.risk.score}/100 "
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
                        f"  Persistence failed for {address}: {exc}"
                    )
                )

        self.stdout.write("")
        self.stdout.write(
            self.style.NOTICE(
                "Scan complete"
            )
        )
        self.stdout.write(
            f"DEX pools discovered: {discovery.pool_count}"
        )
        self.stdout.write(
            f"Token contracts discovered: "
            f"{discovery_result.token_count}"
        )
        self.stdout.write(
            f"Token scans persisted: {persisted_count}"
        )
        self.stdout.write(
            f"Alerts created: {alert_count}"
        )
        self.stdout.write(
            f"Failed persistence operations: {failed_count}"
        )

        if failed_count:
            self.stdout.write(
                self.style.WARNING(
                    "One or more token observations could not be persisted."
                )
            )

    @staticmethod
    def _get_rpc_url(network):
        """
        Resolve the configured Ethereum RPC URL without hard-coding
        credentials.
        """

        for attribute in (
            "rpc_url",
            "http_rpc_url",
            "endpoint",
            "url",
        ):
            value = getattr(network, attribute, None)

            if isinstance(value, str) and value.strip():
                return value.strip()

        return ""

    @staticmethod
    def _resolve_block_range(
        *,
        rpc_url: str,
        from_block: int | None,
        to_block: int | None,
        blocks: int,
    ) -> tuple[int, int]:
        """
        Resolve a bounded Ethereum block range.

        The scanner deliberately limits live discovery to 100 blocks per
        invocation. This prevents an accidental large historical RPC scan.
        """

        if blocks < 1:
            raise CommandError(
                "--blocks must be at least 1."
            )

        if blocks > 100:
            raise CommandError(
                "--blocks cannot exceed 100."
            )

        if (
            from_block is not None
            and to_block is not None
        ):
            start_block = int(from_block)
            end_block = int(to_block)

            if start_block < 0:
                raise CommandError(
                    "--from-block cannot be negative."
                )

            if end_block < 0:
                raise CommandError(
                    "--to-block cannot be negative."
                )

            if end_block < start_block:
                raise CommandError(
                    "--to-block must be greater than or equal "
                    "to --from-block."
                )

            if end_block - start_block + 1 > 100:
                raise CommandError(
                    "The explicit block range cannot exceed 100 blocks."
                )

            return start_block, end_block

        if (
            from_block is not None
            or to_block is not None
        ):
            raise CommandError(
                "Provide both --from-block and --to-block, "
                "or provide neither."
            )

        try:
            from web3 import Web3

            web3 = Web3(
                Web3.HTTPProvider(
                    rpc_url,
                    request_kwargs={
                        "timeout": 10,
                    },
                )
            )

            if not web3.is_connected():
                raise CommandError(
                    "Unable to connect to Ethereum Mainnet RPC."
                )

            latest_block = int(
                web3.eth.block_number
            )

        except CommandError:
            raise

        except Exception as exc:
            raise CommandError(
                "Unable to determine the latest Ethereum block."
            ) from exc

        end_block = latest_block
        start_block = max(
            0,
            end_block - blocks + 1,
        )

        return start_block, end_block
