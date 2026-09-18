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

from domainspyder.config import AUTHOR, DESCRIPTION, VERSION

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


def print_banner(console: Console | None = None) -> None:
    """Print the full DomainSpyder banner to the terminal."""
    console = console or Console()

    spider_text = Text(SPIDER_ART, style="cyan")

    title_text = Text(TITLE_BLOCK, style="bold cyan")
    info_line = Text("\n" + " " * 12)

    info_line.append(f"v{VERSION}", style="bold white")
    info_line.append("  |  ", style="dim")
    info_line.append(DESCRIPTION, style="dim cyan")
    info_line.append("  |  ", style="dim")
    info_line.append(f"by {AUTHOR}", style="dim")
    info_line.append("\n")
    info_line.append(" " * 10 + "=" * 62, style="dim cyan")

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
