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
    """
    Produce a plain dict of headers with all header names lowercased.
    
    Parameters:
        raw (httpx.Headers): Source headers to normalize.
    
    Returns:
        dict[str, str]: Mapping of lowercased header names to their original values.
    """
    return {k.lower(): v for k, v in raw.items()}


def header_blob(*values: str) -> str:
    """
    Builds a single lowercase search blob from multiple header values.
    
    Parameters:
    	values (str): One or more header value strings; falsy values (empty strings, None) are ignored.
    
    Returns:
    	search_blob (str): The provided values lowercased and concatenated with single spaces between them.
    """
    return " ".join(v.lower() for v in values if v)


def boost(candidate: dict[str, int], signals: int, score: int) -> None:
    """
    Add signals and score to a candidate accumulator, clamping the score to a maximum of 10.
    
    Parameters:
        candidate (dict[str, int]): Accumulator with integer keys "signals" and "score"; modified in-place.
        signals (int): Number of signals to add to `candidate["signals"]`.
        score (int): Score increment to add to `candidate["score"]`; the resulting score is capped at 10.
    """
    candidate["signals"] += signals
    candidate["score"] = min(10, candidate["score"] + score)


def confidence_label(score: int) -> str:
    """
    Convert a numeric score into a confidence tier.
    
    Parameters:
        score (int): Integer score used to determine the confidence label.
    
    Returns:
        str: `'High'` if score >= 8, `'Medium'` if score >= 5, `'Low'` otherwise.
    """
    if score >= 8:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def finalize_all(
    candidates: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """
    Produce final display-ready detection entries from candidate accumulators, sorted by score descending.
    
    Parameters:
        candidates (dict[str, dict[str, int]]): Mapping of candidate name to an accumulator with keys
            `"signals"` (number of evidence signals) and `"score"` (raw integer score).
    
    Returns:
        list[dict[str, Any]]: A list of detection dictionaries for candidates that have at least one signal
        and a raw score of 3 or greater. Each detection contains:
            - "name" (str): candidate name
            - "score" (int): score clamped to the range 1..10
            - "confidence" (str): confidence label computed from the clamped score
            - "meter" (str): 10-character progress bar using "█" for filled units and "░" for remaining units
    
    """
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
    """
    Create a new candidate accumulator for scoring detections.
    
    Returns:
        dict[str, int]: Dictionary with keys `"signals"` and `"score"`, both initialized to 0.
    """
    return {"signals": 0, "score": 0}
