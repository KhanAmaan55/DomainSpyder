"""Tests for shared tech detection scoring utilities."""

from domainspyder.sources.tech.helpers import (
    boost,
    confidence_label,
    finalize_all,
    header_blob,
    lower_headers,
    new_candidate,
)


class TestLowerHeaders:
    def test_lowercases_keys(self):
        raw = {"Content-Type": "text/html", "Server": "nginx"}
        result = lower_headers(raw)
        assert result == {"content-type": "text/html", "server": "nginx"}

    def test_preserves_values(self):
        raw = {"X-Custom": "Value"}
        result = lower_headers(raw)
        assert result["x-custom"] == "Value"


class TestHeaderBlob:
    def test_joins_values(self):
        result = header_blob("Hello", "World")
        assert result == "hello world"

    def test_filters_falsy(self):
        result = header_blob("Hello", "", None)  # type: ignore[arg-type]
        assert result == "hello"

    def test_empty(self):
        assert header_blob() == ""


class TestNewCandidate:
    def test_creates_candidate(self):
        c = new_candidate()
        assert c == {"signals": 0, "score": 0}

    def test_independent_candidates(self):
        c1 = new_candidate()
        c2 = new_candidate()
        c1["signals"] = 5
        assert c2["signals"] == 0


class TestBoost:
    def test_boosts_score_and_signals(self):
        c = new_candidate()
        boost(c, 2, 5)
        assert c["signals"] == 2
        assert c["score"] == 5

    def test_score_capped_at_10(self):
        c = new_candidate()
        boost(c, 1, 15)
        assert c["score"] == 10

    def test_multiple_boosts(self):
        c = new_candidate()
        boost(c, 1, 3)
        boost(c, 2, 4)
        assert c["signals"] == 3
        assert c["score"] == 7


class TestConfidenceLabel:
    def test_high(self):
        assert confidence_label(10) == "High"
        assert confidence_label(8) == "High"
        assert confidence_label(9) == "High"

    def test_medium(self):
        assert confidence_label(5) == "Medium"
        assert confidence_label(6) == "Medium"
        assert confidence_label(7) == "Medium"

    def test_low(self):
        assert confidence_label(0) == "Low"
        assert confidence_label(1) == "Low"
        assert confidence_label(3) == "Low"
        assert confidence_label(4) == "Low"


class TestFinalizeAll:
    def test_filters_low_scores(self):
        candidates = {
            "Good": {"signals": 3, "score": 8},
            "Bad": {"signals": 0, "score": 0},
            "Weak": {"signals": 1, "score": 2},
        }
        results = finalize_all(candidates)
        names = [r["name"] for r in results]
        assert "Good" in names
        assert "Bad" not in names
        assert "Weak" not in names

    def test_sorts_by_score_descending(self):
        candidates = {
            "A": {"signals": 1, "score": 5},
            "B": {"signals": 3, "score": 9},
            "C": {"signals": 2, "score": 7},
        }
        results = finalize_all(candidates)
        scores = [r["score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_result_structure(self):
        candidates = {"Test": {"signals": 2, "score": 7}}
        results = finalize_all(candidates)
        assert len(results) == 1
        r = results[0]
        assert r["name"] == "Test"
        assert r["score"] == 7
        assert r["confidence"] == "Medium"
        assert len(r["meter"]) == 10
        assert "█" in r["meter"]

    def test_score_clamping(self):
        candidates = {"High": {"signals": 5, "score": 15}}
        results = finalize_all(candidates)
        assert results[0]["score"] == 10
        # Score of 0 with no signals is filtered
        candidates2 = {"Filtered": {"signals": 0, "score": 0}}
        results2 = finalize_all(candidates2)
        assert len(results2) == 0

    def test_empty_candidates(self):
        assert finalize_all({}) == []
