"""
DomainSpyder ASCII banner.

Renders the DOMAIN SPYDER branding and ASCII spider art
using Rich markup.  No emojis are used anywhere.
"""

from __future__ import annotations

from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from domainspyder.config import AUTHOR, REPO_URL, VERSION

# ---------------------------------------------------------------------------
# ASCII Spider Art
# ---------------------------------------------------------------------------

SPIDER_ART = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠶⡄⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⠤⣤⡀⢀⡗⠒⣧⠴⠋⠚⠉⠙⠳⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡞⢁⣠⡟⠻⣎⠃⢰⠏⠀⠀⠀⠀⠀⠀⢘⣧⣤⣄⡀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⠞⠓⡶⢦⣻⡄⣨⠷⠚⠒⠶⡤⠀⠀⢀⡴⠋⠁⢠⣇⠙⢳⣄⠀
⠀⠀⠀⢠⣞⠁⣠⠶⢧⣄⠈⣿⠳⠶⢤⣀⠀⠈⢩⠴⠟⠛⣯⠙⢳⡌⠻⣯⡘⡆
⠀⠀⢠⠏⢈⡟⠁⢀⣠⣤⠖⣿⡤⣄⣀⠙⢧⣀⣸⡀⠘⣦⡛⢳⡴⠻⣄⠈⠉⠁
⢀⣴⠟⢳⡞⢀⡴⠋⠀⣼⠗⡿⢠⡏⢹⣇⣤⡽⢫⡉⢻⡁⢹⡄⠻⣄⣸⠧⣄⡀
⠘⠶⠖⠋⣠⠟⢙⡶⢺⠷⣴⠛⠺⢦⡾⠐⣾⣇⣼⡇⠀⣟⠋⢷⠀⠈⠳⢤⡤⠇
⠀⠀⠀⣴⠛⣦⠏⠀⣼⣀⡏⠀⠀⣼⠦⣾⠉⡇⠸⠇⠀⢹⣀⣸⡆⠀⠀⠀⠀⠀
⠀⠀⡼⢧⣴⠃⠀⢸⣃⡼⠁⠀⠀⣿⣤⣿⠀⡟⠉⣇⠀⠀⢿⡀⢻⡀⠀⠀⠀⠀
⠀⠸⣇⡼⠃⠀⠀⠀⠉⠀⠀⠀⠀⠹⣤⡿⠀⢿⣠⣿⠀⠀⠀⠙⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

# ---------------------------------------------------------------------------
# Title block
# ---------------------------------------------------------------------------

TITLE_BLOCK = r"""
     ____   ___  __  __    _    ___ _   _   ____  ______   ______  _____ ____
    |  _ \ / _ \|  \/  |  / \  |_ _| \ | | / ___||  _ \ \ / /  _ \| ____|  _ \
    | | | | | | | |\/| | / _ \  | ||  \| | \___ \| |_) \ V /| | | |  _| | |_) |
    | |_| | |_| | |  | |/ ___ \ | || |\  |  ___) |  __/ | | | |_| | |___|  _ <
    |____/ \___/|_|  |_/_/   \_\___|_| \_| |____/|_|    |_| |____/|_____|_| \_\
"""

_TITLE_LINES = [line for line in TITLE_BLOCK.splitlines() if line.strip()]
_TITLE_LEFT = min(len(line) - len(line.lstrip()) for line in _TITLE_LINES)
_TITLE_RIGHT = max(len(line.rstrip()) for line in _TITLE_LINES)


def _centre_pad(width: int) -> str:
    """Return the indent that centres a line of *width* under the title."""
    return " " * (_TITLE_LEFT + (_TITLE_RIGHT - _TITLE_LEFT - width) // 2)


def print_banner(console: Console | None = None) -> None:
    """Print the full DomainSpyder banner to the terminal."""
    console = console or Console()

    spider_text = Text(SPIDER_ART, style="cyan")

    title_text = Text(TITLE_BLOCK, style="bold cyan")

    info = Text()
    info.append(f"v{VERSION}", style="bold white")
    info.append("  |  ", style="dim")
    # Clickable in terminals that support hyperlinks.
    info.append(REPO_URL.removeprefix("https://"), style=f"dim cyan link {REPO_URL}")
    info.append("  |  ", style="dim")
    info.append(f"by {AUTHOR}", style="dim")

    # The rule overhangs the info line by two columns on each side.
    rule_width = len(info) + 4
    info_line = Text.assemble(
        "\n",
        _centre_pad(len(info)),
        info,
        "\n",
        (_centre_pad(rule_width) + "=" * rule_width, "dim cyan"),
    )

    right_block = Text.assemble(title_text, "\n", info_line)
    right_block = Padding(Align.center(right_block), (2, 0))

    console.print(
        Columns(
            [spider_text, right_block],
            padding=(0, 2),
            align="center",
        ),
        highlight=False,
    )
    console.print()
