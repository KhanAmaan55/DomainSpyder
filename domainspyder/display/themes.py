"""
DomainSpyder terminal colour and style definitions.

All Rich markup styles are defined here so the rest of the
application uses consistent visual language.
"""

# ---------------------------------------------------------------------------
# Semantic colours  (Rich markup strings)
# ---------------------------------------------------------------------------

ACCENT        = "bold cyan"
ACCENT_DIM    = "cyan"
HEADING       = "bold white"
SUBHEADING    = "bold cyan"
SUCCESS       = "bold green"
SUCCESS_DIM   = "green"
WARNING       = "bold yellow"
WARNING_DIM   = "yellow"
ERROR         = "bold red"
ERROR_DIM     = "red"
MUTED         = "dim"
INFO          = "bold magenta"
LABEL         = "bold white"
VALUE         = "cyan"
SEPARATOR     = "dim cyan"

# ---------------------------------------------------------------------------
# Table styles
# ---------------------------------------------------------------------------

TABLE_HEADER  = "bold white"
TABLE_BORDER  = "cyan"
TABLE_ROW_DIM = "dim"

# ---------------------------------------------------------------------------
# Score thresholds → colour
# ---------------------------------------------------------------------------


def score_color(score: int) -> str:
    """Return a Rich colour name based on a 0-10 score."""
    if score >= 8:
        return "green"
    if score >= 5:
        return "yellow"
    return "red"
