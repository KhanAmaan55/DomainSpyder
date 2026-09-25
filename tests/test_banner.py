"""Tests for the CLI banner."""

from rich.console import Console

from domainspyder.config import AUTHOR, REPO_URL
from domainspyder.display.banner import print_banner


def test_banner_credits_author_and_links_repo():
    console = Console(record=True, width=130, color_system=None)
    print_banner(console)
    output = console.export_text()
    assert f"by {AUTHOR}" in output
    assert REPO_URL.removeprefix("https://") in output
