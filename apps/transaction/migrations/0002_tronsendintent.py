import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("blockchain", "0003_alter_blockchainnetwork_options_and_more"),
        ("transaction", "0001_initial"),
        ("wallet", "0004_walletvault"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TronSendIntent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("idempotency_key", models.UUIDField()),
                ("status", models.CharField(choices=[("prepared", "Prepared"), ("broadcasting", "Broadcasting"), ("submitted", "Submitted"), ("outcome_unknown", "Outcome unknown"), ("rejected", "Rejected"), ("expired", "Expired")], db_index=True, default="prepared", max_length=24)),
                ("asset", models.CharField(max_length=20)),
                ("sender", models.CharField(max_length=64)),
                ("recipient", models.CharField(max_length=64)),
                ("amount", models.DecimalField(decimal_places=18, max_digits=36)),
                ("estimated_fee_trx", models.DecimalField(decimal_places=6, max_digits=24)),
                ("estimated_energy", models.PositiveBigIntegerField(default=0)),
                ("unsigned_transaction", models.JSONField()),
                ("transaction_hash", models.CharField(blank=True, db_index=True, max_length=64)),
                ("error_code", models.CharField(blank=True, max_length=80)),
                ("error_message", models.CharField(blank=True, max_length=255)),
                ("expires_at", models.DateTimeField()),
                ("submitted_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("network", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="tron_send_intents", to="blockchain.blockchainnetwork")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tron_send_intents", to=settings.AUTH_USER_MODEL)),
                ("wallet", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="tron_send_intents", to="wallet.wallet")),
            ],
            options={
                "db_table": "tron_send_intents",
                "ordering": ["-created_at"],
                "constraints": [models.UniqueConstraint(fields=("user", "idempotency_key"), name="unique_tron_send_idempotency")],
            },
        ),
    ]
