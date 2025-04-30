"""Command-line interface."""
import fire

from security_cli.action import Action
from security_cli.config import ConfigManager


def main() -> None:
    """Main entry point for the command line interface of security-cli project."""
    fire.Fire({
        "config": ConfigManager,
        "enrich": Action().enrich
    })


if __name__ == "__main__":
    main()
