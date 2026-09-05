from django.core.management.base import BaseCommand

from apps.blockchain.models import Asset, BlockchainNetwork


NETWORKS = [
    {
        "name": "Ethereum Mainnet",
        "slug": "ethereum-mainnet",
        "symbol": "ETH",
        "chain_id": 1,
        "is_testnet": False,
        "is_active": True,
        "assets": [
            {
                "symbol": "ETH",
                "name": "Ethereum",
                "token_standard": Asset.TokenStandard.NATIVE,
                "contract_address": "",
                "decimals": 18,
                "is_native": True,
                "is_active": True,
            },
        ],
    },
    {
        "name": "Bitcoin Mainnet",
        "slug": "bitcoin-mainnet",
        "symbol": "BTC",
        "chain_id": None,
        "is_testnet": False,
        "is_active": True,
        "assets": [
            {
                "symbol": "BTC",
                "name": "Bitcoin",
                "token_standard": Asset.TokenStandard.NATIVE,
                "contract_address": "",
                "decimals": 8,
                "is_native": True,
                "is_active": True,
            },
        ],
    },
    {
        "name": "Tron Mainnet",
        "slug": "tron-mainnet",
        "symbol": "TRX",
        "chain_id": 728126428,
        "is_testnet": False,
        "is_active": True,
        "assets": [
            {
                "symbol": "TRX",
                "name": "TRON",
                "token_standard": Asset.TokenStandard.NATIVE,
                "contract_address": "",
                "decimals": 6,
                "is_native": True,
                "is_active": True,
            },
        ],
    },
]


class Command(BaseCommand):
    help = (
        "Provision supported blockchain networks and their native assets."
    )

    def handle(self, *args, **options):
        network_count = 0
        asset_count = 0

        for network_data in NETWORKS:
            assets = network_data["assets"]

            network_defaults = {
                key: value
                for key, value in network_data.items()
                if key != "assets"
            }

            network, network_created = (
                BlockchainNetwork.objects.update_or_create(
                    slug=network_data["slug"],
                    defaults=network_defaults,
                )
            )

            if network_created:
                network_count += 1
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Created network: {network.name}"
                    )
                )
            else:
                self.stdout.write(
                    f"Updated network: {network.name}"
                )

            for asset_data in assets:
                asset, asset_created = Asset.objects.update_or_create(
                    network=network,
                    symbol=asset_data["symbol"],
                    contract_address=asset_data["contract_address"],
                    defaults=asset_data,
                )

                if asset_created:
                    asset_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  Created asset: "
                            f"{asset.symbol} ({network.name})"
                        )
                    )
                else:
                    self.stdout.write(
                        f"  Updated asset: "
                        f"{asset.symbol} ({network.name})"
                    )

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                "Blockchain provisioning complete."
            )
        )
        self.stdout.write(
            f"Networks created: {network_count}"
        )
        self.stdout.write(
            f"Assets created: {asset_count}"
        )
        self.stdout.write(
            f"Active networks: "
            f"{BlockchainNetwork.objects.filter(is_active=True).count()}"
        )
        self.stdout.write(
            f"Active assets: "
            f"{Asset.objects.filter(is_active=True).count()}"
        )
