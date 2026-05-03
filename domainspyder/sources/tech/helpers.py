"""
Shared scoring utilities for technology detection.

Every detector uses the same scoring system: candidates accumulate
signals and a score (0-10).  ``finalize_all`` converts those raw
numbers into display-ready dicts with confidence labels and meters.
"""

from __future__ import annotations

from typing import Any

import httpx


def lower_headers(raw: httpx.Headers) -> dict[str, str]:
    """Return a plain dict with all header keys lower-cased."""
    return {k.lower(): v for k, v in raw.items()}


def header_blob(*values: str) -> str:
    """Concatenate header values into one lower-cased search string."""
    return " ".join(v.lower() for v in values if v)


def boost(candidate: dict[str, int], signals: int, score: int) -> None:
    """Accumulate evidence for a technology candidate, capping at 10."""
    candidate["signals"] += signals
    candidate["score"] = min(10, candidate["score"] + score)


def confidence_label(score: int) -> str:
    """Map a numeric score to a human-readable confidence label."""
    if score >= 8:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def finalize_all(
    candidates: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Return all valid detections sorted by score descending."""
    results: list[dict[str, Any]] = []
    for name, data in candidates.items():
        if data["signals"] <= 0 or data["score"] < 3:
            continue
        score = min(10, max(1, data["score"]))
        results.append({
            "name": name,
            "score": score,
            "confidence": confidence_label(score),
            "meter": "█" * score + "░" * (10 - score),
        })
    return sorted(results, key=lambda x: x["score"], reverse=True)


def new_candidate() -> dict[str, int]:
    """Return a fresh candidate accumulator."""
    return {"signals": 0, "score": 0}
