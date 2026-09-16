from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("trading", "0002_order_exchange_client_order_id_and_more")]

    operations = [
        migrations.AlterField(
            model_name="order",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("submitting", "Submitting"),
                    ("unknown", "Unknown"),
                    ("cancelling", "Cancelling"),
                    ("cancel_unknown", "Cancellation Unknown"),
                    ("open", "Open"),
                    ("partially_filled", "Partially Filled"),
                    ("filled", "Filled"),
                    ("cancelled", "Cancelled"),
                    ("rejected", "Rejected"),
                    ("failed", "Failed"),
                ],
                db_index=True,
                default="pending",
                max_length=30,
            ),
        ),
    ]
