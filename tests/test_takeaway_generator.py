"""
tests/test_takeaway_generator.py — Tests unitaires pour TakeawayGenerator.

Vérifie que les synthèses rule-based produisent des sorties cohérentes
sans aucune dépendance IA/LLM/NLP.
"""

from __future__ import annotations

import pytest
from collections import Counter
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_article(
    severity="INFO",
    risk_score=20,
    strat_score=0,
    exploit_available=False,
    ransomware_related=False,
    apt_related=False,
    nuclear_related=False,
    conflict_related=False,
    leak_related=False,
    in_kev=False,
    cves=None,
    actors=None,
    theatres=None,
    source="TestSource",
    iocs=None,
    published=None,
    title="Test Article",
    summary="Test summary",
):
    """Crée un dict article avec les champs nécessaires à TakeawayGenerator."""
    return {
        "severity": severity,
        "risk_score": risk_score,
        "strat_score": strat_score,
        "exploit_available": exploit_available,
        "ransomware_related": ransomware_related,
        "apt_related": apt_related,
        "nuclear_related": nuclear_related,
        "conflict_related": conflict_related,
        "leak_related": leak_related,
        "in_kev": in_kev,
        "cves": cves or [],
        "actors": actors or [],
        "theatres": theatres or [],
        "source": source,
        "iocs": iocs or {},
        "published": published or datetime.now(timezone.utc).isoformat(),
        "title": title,
        "summary": summary,
        "link": "https://example.com",
        "category": "Cyber",
        "cvss_score": None,
        "darkweb_related": False,
        "aerospace_related": False,
        "weapons_related": False,
        "leak_records": None,
        "id": "test123",
    }


@pytest.fixture
def empty_articles():
    return []


@pytest.fixture
def mixed_articles():
    return [
        _make_article(severity="CRITICAL", risk_score=90, exploit_available=True,
                      cves=["CVE-2024-1111"], actors=["Russia"], theatres=["ukraine"]),
        _make_article(severity="HIGH", risk_score=75, ransomware_related=True,
                      actors=["China"], theatres=["asia-pacific"]),
        _make_article(severity="CRITICAL", risk_score=88, apt_related=True,
                      actors=["Russia"], theatres=["ukraine"]),
        _make_article(severity="MEDIUM", risk_score=50),
        _make_article(severity="INFO", risk_score=15),
    ]


@pytest.fixture
def stats_basic(mixed_articles):
    return {
        "total": len(mixed_articles),
        "critical_count": 2,
        "flash_count": 0,
        "exploit_count": 1,
        "ransomware_count": 1,
        "apt_count": 1,
        "nuclear_count": 0,
        "conflict_count": 0,
        "kev_count": 0,
        "leak_count": 0,
        "avg_risk_score": 63.6,
        "by_theatre": Counter({"ukraine": 2, "asia-pacific": 1}),
        "by_actor": Counter({"Russia": 2, "China": 1}),
        "top_cves": [("CVE-2024-1111", 1)],
        "cve_count": 1,
        "iocs_total": 0,
        "by_date": {"24h": 3, "7d": 2},
    }


# ---------------------------------------------------------------------------
# Tests daily_brief
# ---------------------------------------------------------------------------

class TestDailyBrief:
    def test_returns_dict_with_required_keys(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        brief = gen.daily_brief()

        assert isinstance(brief, dict)
        for key in ("generated_at", "period", "headline", "threat_level", "sections"):
            assert key in brief, f"Missing key: {key}"

    def test_threat_level_critique_when_critical_ge3(self, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        articles = [
            _make_article(severity="CRITICAL", risk_score=90) for _ in range(3)
        ]
        stats = dict(stats_basic)
        stats["critical_count"] = 3
        gen = TakeawayGenerator(articles, stats, {})
        brief = gen.daily_brief()
        assert brief["threat_level"] == "CRITIQUE"

    def test_threat_level_faible_when_low_scores(self, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        articles = [_make_article(risk_score=10) for _ in range(3)]
        stats = dict(stats_basic)
        stats["critical_count"] = 0
        stats["flash_count"] = 0
        stats["avg_risk_score"] = 10
        gen = TakeawayGenerator(articles, stats, {})
        brief = gen.daily_brief()
        assert brief["threat_level"] in ("FAIBLE", "MODÉRÉ")

    def test_headline_is_nonempty_string(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        brief = gen.daily_brief()
        assert isinstance(brief["headline"], str)
        assert len(brief["headline"]) > 0

    def test_sections_is_list(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        brief = gen.daily_brief()
        assert isinstance(brief["sections"], list)
        for sec in brief["sections"]:
            assert "title" in sec
            assert "items" in sec
            assert isinstance(sec["items"], list)

    def test_empty_articles_returns_valid_brief(self, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        stats = dict(stats_basic)
        stats["total"] = 0
        stats["critical_count"] = 0
        stats["flash_count"] = 0
        stats["avg_risk_score"] = 0
        gen = TakeawayGenerator([], stats, {})
        brief = gen.daily_brief()
        assert isinstance(brief, dict)
        assert brief["threat_level"] == "FAIBLE"

    def test_generated_at_is_iso_string(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        brief = gen.daily_brief()
        # Should parse without error
        datetime.fromisoformat(brief["generated_at"].replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Tests weekly_strategic
# ---------------------------------------------------------------------------

class TestWeeklyStrategic:
    def test_returns_dict_with_required_keys(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        weekly = gen.weekly_strategic()

        assert isinstance(weekly, dict)
        for key in ("generated_at", "period", "headline", "sections"):
            assert key in weekly, f"Missing key: {key}"

    def test_sections_nonempty_for_active_week(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        weekly = gen.weekly_strategic()
        assert len(weekly["sections"]) > 0


# ---------------------------------------------------------------------------
# Tests incident_flash
# ---------------------------------------------------------------------------

class TestIncidentFlash:
    def test_returns_dict_with_required_keys(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        article = mixed_articles[0]
        flash = gen.incident_flash(article)

        for key in ("generated_at", "classification", "incident",
                    "actors", "theatres", "assessment", "recommended_actions"):
            assert key in flash, f"Missing key: {key}"

    def test_classification_exploit_for_exploit_article(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        article = _make_article(exploit_available=True)
        flash = gen.incident_flash(article)
        assert isinstance(flash["classification"], str)
        assert len(flash["classification"]) > 0

    def test_recommended_actions_is_nonempty_list(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        flash = gen.incident_flash(mixed_articles[0])
        assert isinstance(flash["recommended_actions"], list)
        assert len(flash["recommended_actions"]) > 0

    def test_incident_dict_has_title_and_source(self, mixed_articles, stats_basic):
        from analyzers.takeaway_generator import TakeawayGenerator
        gen = TakeawayGenerator(mixed_articles, stats_basic, {})
        flash = gen.incident_flash(mixed_articles[0])
        inc = flash["incident"]
        assert "title" in inc
        assert "source" in inc
