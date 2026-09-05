import os
import sys
import subprocess
import platform
from pathlib import Path


# ============================================================
# HAPPYWallet Launcher
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent
MANAGE_PY = PROJECT_ROOT / "manage.py"


# ============================================================
# Configuration
# ============================================================

APP_NAME = "HappyWallet"
APP_VERSION = "0.1.0"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8000"


# ============================================================
# Terminal helpers
# ============================================================

def print_banner():
    print()
    print("=" * 60)
    print(f"             {APP_NAME}")
    print(f"             Version {APP_VERSION}")
    print("=" * 60)
    print()


def print_info(message):
    print(f"[INFO] {message}")


def print_warning(message):
    print(f"[WARNING] {message}")


def print_error(message):
    print(f"[ERROR] {message}")


# ============================================================
# Environment
# ============================================================

def set_environment():
    """
    Configure the Django environment.

    The actual Django settings package is selected through
    HAPPYWallet_SETTINGS.
    """

    settings_module = os.environ.get(
        "HAPPYWallet_SETTINGS",
        "config.settings.desktop"
    )

    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE",
        settings_module
    )

    return settings_module


# ============================================================
# Project validation
# ============================================================

def validate_project():
    """
    Make sure the launcher is being executed from a valid
    HappyWallet Django project.
    """

    if not MANAGE_PY.exists():
        print_error(
            "manage.py was not found."
        )
        print_error(
            f"Expected location: {MANAGE_PY}"
        )
        return False

    config_directory = PROJECT_ROOT / "config"

    if not config_directory.exists():
        print_warning(
            "config/ directory was not found."
        )

    apps_directory = PROJECT_ROOT / "apps"

    if not apps_directory.exists():
        print_warning(
            "apps/ directory was not found."
        )

    return True


# ============================================================
# Storage initialization
# ============================================================

def initialize_storage():
    """
    Create application storage directories.

    No private keys or wallet secrets are generated here.
    """

    directories = [
        PROJECT_ROOT / "storage",
        PROJECT_ROOT / "storage" / "vault",
        PROJECT_ROOT / "storage" / "logs",
        PROJECT_ROOT / "storage" / "exports",
        PROJECT_ROOT / "storage" / "imports",
    ]

    for directory in directories:
        directory.mkdir(
            parents=True,
            exist_ok=True
        )

    print_info("Storage directories initialized.")


# ============================================================
# USB directory initialization
# ============================================================

def initialize_usb_directory():
    """
    Create the local USB integration directory.

    Actual USB detection/mounting will be handled by the
    usb_manager application later.
    """

    usb_directory = PROJECT_ROOT / "usb" / "HappyWallet"

    usb_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    print_info(
        f"USB integration directory: {usb_directory}"
    )


# ============================================================
# Python environment
# ============================================================

def check_python():
    version = sys.version_info

    print_info(
        f"Python {version.major}.{version.minor}.{version.micro}"
    )

    if version < (3, 10):
        print_error(
            "HappyWallet requires Python 3.10 or newer."
        )
        return False

    return True


# ============================================================
# Django check
# ============================================================

def django_check(settings_module):
    """
    Run Django's system check before starting the server.
    """

    print_info(
        f"Using Django settings: {settings_module}"
    )

    command = [
        sys.executable,
        str(MANAGE_PY),
        "check",
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT
    )

    return result.returncode == 0


# ============================================================
# Database migrations
# ============================================================

def run_migrations():
    """
    Apply database migrations.

    This is useful during development.

    For production/cold-wallet deployment, migrations should
    eventually be handled explicitly rather than blindly
    applying them at every startup.
    """

    print_info("Checking database migrations...")

    command = [
        sys.executable,
        str(MANAGE_PY),
        "migrate",
        "--noinput",
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT
    )

    return result.returncode == 0


# ============================================================
# Server
# ============================================================

def start_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    """
    Start Django development server.
    """

    print()
    print("=" * 60)
    print("HappyWallet is starting...")
    print("=" * 60)

    print()
    print(f"URL: http://{host}:{port}/")
    print()
    print("Press CTRL+C to stop the server.")
    print()

    command = [
        sys.executable,
        str(MANAGE_PY),
        "runserver",
        f"{host}:{port}",
    ]

    try:
        subprocess.run(
            command,
            cwd=PROJECT_ROOT
        )

    except KeyboardInterrupt:
        print()
        print_info("HappyWallet stopped.")


# ============================================================
# Command-line arguments
# ============================================================

def parse_arguments():
    """
    Supported commands:

        python start_wallet.py
        python start_wallet.py --host 127.0.0.1
        python start_wallet.py --port 8000
        python start_wallet.py --settings desktop
        python start_wallet.py --check
        python start_wallet.py --migrate
    """

    arguments = sys.argv[1:]

    options = {
        "host": DEFAULT_HOST,
        "port": DEFAULT_PORT,
        "settings": None,
        "check": False,
        "migrate": False,
    }

    index = 0

    while index < len(arguments):

        argument = arguments[index]

        if argument == "--host":
            if index + 1 >= len(arguments):
                print_error("--host requires a value.")
                sys.exit(1)

            options["host"] = arguments[index + 1]
            index += 2
            continue

        if argument == "--port":
            if index + 1 >= len(arguments):
                print_error("--port requires a value.")
                sys.exit(1)

            options["port"] = arguments[index + 1]
            index += 2
            continue

        if argument == "--settings":
            if index + 1 >= len(arguments):
                print_error("--settings requires a value.")
                sys.exit(1)

            options["settings"] = arguments[index + 1]
            index += 2
            continue

        if argument == "--check":
            options["check"] = True
            index += 1
            continue

        if argument == "--migrate":
            options["migrate"] = True
            index += 1
            continue

        if argument in ("--help", "-h"):
            print_help()
            sys.exit(0)

        print_warning(
            f"Unknown argument: {argument}"
        )

        index += 1

    return options


# ============================================================
# Help
# ============================================================

def print_help():
    print()
    print("HappyWallet Launcher")
    print()
    print("Usage:")
    print()
    print("  python start_wallet.py")
    print()
    print("Options:")
    print()
    print("  --host ADDRESS")
    print("      Set development server host.")
    print()
    print("  --port PORT")
    print("      Set development server port.")
    print()
    print("  --settings MODE")
    print("      Select settings mode.")
    print("      desktop")
    print("      online")
    print("      portable")
    print()
    print("  --check")
    print("      Run Django system checks only.")
    print()
    print("  --migrate")
    print("      Apply database migrations and exit.")
    print()
    print("  --help")
    print("      Show this help message.")
    print()


# ============================================================
# Settings mode
# ============================================================

def configure_settings(settings_mode):
    """
    Convert a simple mode name into a Django settings module.
    """

    if not settings_mode:
        return set_environment()

    settings_map = {
        "desktop": "config.settings.desktop",
        "online": "config.settings.online",
        "portable": "config.settings.portable",
        "base": "config.settings.base",
    }

    settings_mode = settings_mode.lower()

    if settings_mode not in settings_map:
        print_error(
            f"Unknown settings mode: {settings_mode}"
        )

        print(
            "Available modes: desktop, online, portable"
        )

        sys.exit(1)

    settings_module = settings_map[settings_mode]

    os.environ["DJANGO_SETTINGS_MODULE"] = settings_module

    return settings_module


# ============================================================
# Main
# ============================================================

def main():
    print_banner()

    # --------------------------------------------------------
    # Validate Python
    # --------------------------------------------------------

    if not check_python():
        sys.exit(1)

    # --------------------------------------------------------
    # Validate project
    # --------------------------------------------------------

    if not validate_project():
        sys.exit(1)

    # --------------------------------------------------------
    # Parse arguments
    # --------------------------------------------------------

    options = parse_arguments()

    # --------------------------------------------------------
    # Configure Django
    # --------------------------------------------------------

    settings_module = configure_settings(
        options["settings"]
    )

    # --------------------------------------------------------
    # Initialize directories
    # --------------------------------------------------------

    initialize_storage()
    initialize_usb_directory()

    # --------------------------------------------------------
    # Django system check
    # --------------------------------------------------------

    if not django_check(settings_module):
        print_error(
            "Django system check failed."
        )
        sys.exit(1)

    # --------------------------------------------------------
    # Check only
    # --------------------------------------------------------

    if options["check"]:
        print()
        print_info(
            "Django system check completed successfully."
        )
        return

    # --------------------------------------------------------
    # Migration
    # --------------------------------------------------------

    if options["migrate"]:
        if not run_migrations():
            print_error(
                "Database migration failed."
            )
            sys.exit(1)

        print_info(
            "Database migrations completed."
        )

        return

    # --------------------------------------------------------
    # Start server
    # --------------------------------------------------------

    start_server(
        host=options["host"],
        port=options["port"]
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()