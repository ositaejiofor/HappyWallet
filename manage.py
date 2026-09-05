"""
HappyWallet Django management utility.

Default settings:
    config.settings.development

Supported environments:
    development
    production
    portable

Examples:
    python manage.py check

    python manage.py migrate

    python manage.py runserver

    python manage.py check --settings=config.settings.production

    python manage.py check --settings=config.settings.portable
"""

from __future__ import annotations

import os
import sys


# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_SETTINGS_MODULE = "config.settings.development"

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    DEFAULT_SETTINGS_MODULE,
)


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    """Run Django's command-line utility."""

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Django could not be imported. "
            "Make sure the virtual environment is activated "
            "and Django is installed."
        ) from exc

    execute_from_command_line(sys.argv)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
