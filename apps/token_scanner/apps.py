from django.apps import AppConfig


class TokenScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.token_scanner"
    label = "token_scanner"
    verbose_name = "HappyWallet Token Scanner"