"""
tests/test_scoring_engine.py — Tests unitaires pour analyzers/scoring_engine.py

Couvre :
  - Détection faux-positifs (blacklist contextuelle)
  - Anti-inflation CRITICAL (exige exploit ou acteur étatique)
  - Scoring temporel (bonus/malus fraîcheur)
  - Pondération source
  - ScoreBreakdown (décomposition)
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from analyzers.scoring_engine import (
    ScoringEngine,
    ScoreBreakdown,
    compute_freshness_bonus,
    get_source_reliability,
    _contains_false_positive,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """ScoringEngine par défaut."""
    return ScoringEngine(critical_requires_exploit_or_actor=True)


@pytest.fixture
def engine_strict():
    """ScoringEngine avec blacklist personnalisée."""
    return ScoringEngine(
        false_positive_blacklist=["test term custom"],
        critical_requires_exploit_or_actor=True,
    )


# ---------------------------------------------------------------------------
# Tests : faux-positifs
# ---------------------------------------------------------------------------

class TestFalsePositiveDetection:
    def test_nuclear_family_is_false_positive(self):
        """'nuclear family' ne doit pas déclencher d'alerte nucléaire."""
        assert _contains_false_positive("Raising a nuclear family in suburbia") is True

    def test_atomic_clock_is_false_positive(self):
        """'atomic clock' ne doit pas déclencher d'alerte nucléaire."""
        assert _contains_false_positive("The atomic clock was synchronized") is True

    def test_critical_thinking_is_false_positive(self):
        """'critical thinking' ne doit pas classifier CRITICAL."""
        assert _contains_false_positive("Article on critical thinking skills") is True

    def test_nuclear_test_is_not_false_positive(self):
        """'nuclear test' est un vrai signal."""
        assert _contains_false_positive("DPRK conducted nuclear test in sea of Japan") is False

    def test_custom_blacklist_detected(self):
        """La blacklist personnalisée est appliquée."""
        assert _contains_false_positive("test term custom found", ["test term custom"]) is True

    def test_severity_returns_info_for_false_positive(self, engine):
        """Un faux-positif doit retourner INFO indépendamment du titre."""
        severity = engine.compute_severity(
            title="Nuclear family values",
            summary="Article about nuclear family relationships",
            cvss_score=None,
        )
        assert severity == "INFO"


# ---------------------------------------------------------------------------
# Tests : anti-inflation CRITICAL
# ---------------------------------------------------------------------------

class TestCriticalInflation:
    def test_critical_keyword_without_exploit_degrades_to_high(self, engine):
        """CRITICAL sans exploit ni acteur étatique → HIGH (anti-inflation)."""
        severity = engine.compute_severity(
            title="Critical vulnerability in software",
            summary="A critical flaw was discovered in an enterprise application.",
            cvss_score=None,
        )
        # Avec critical_requires_exploit_or_actor=True, doit être HIGH
        assert severity == "HIGH"

    def test_critical_with_exploit_confirmed(self, engine):
        """CRITICAL avec 'actively exploited' reste CRITICAL."""
        severity = engine.compute_severity(
            title="Critical RCE CVE-2024-1234 actively exploited in the wild",
            summary="Proof-of-concept available, attackers leveraging this flaw",
            cvss_score=None,
        )
        assert severity == "CRITICAL"

    def test_critical_with_state_actor_confirmed(self, engine):
        """CRITICAL avec acteur étatique reste CRITICAL."""
        severity = engine.compute_severity(
            title="Critical zero-day used by Fancy Bear APT28",
            summary="Nation-state actors exploiting CVE-2024-5678",
            cvss_score=None,
        )
        assert severity == "CRITICAL"

    def test_flash_unaffected_by_anti_inflation(self, engine):
        """Les évènements FLASH ne sont pas affectés par anti-inflation."""
        severity = engine.compute_severity(
            title="Nuclear launch detected — NORAD confirmation",
            summary="Ballistic missile launch from North Korea",
            cvss_score=None,
        )
        assert severity == "FLASH"

    def test_cvss_9_overrides_to_critical(self, engine):
        """CVSS ≥ 9.0 force CRITICAL même sans autres signaux."""
        severity = engine.compute_severity(
            title="Severe vulnerability",
            summary="Affects enterprise systems",
            cvss_score=9.8,
        )
        assert severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests : scoring temporel (fraîcheur)
# ---------------------------------------------------------------------------

class TestFreshnessScoring:
    def test_article_under_24h_gets_bonus(self):
        """Article < 24h doit recevoir le bonus maximal (+10)."""
        published = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat()
        bonus = compute_freshness_bonus(published)
        assert bonus == 10

    def test_article_under_72h_gets_medium_bonus(self):
        """Article entre 24h et 72h doit recevoir +5."""
        published = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        bonus = compute_freshness_bonus(published)
        assert bonus == 5

    def test_article_over_7d_gets_malus(self):
        """Article > 7j doit recevoir -5."""
        published = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        bonus = compute_freshness_bonus(published)
        assert bonus == -5

    def test_invalid_date_returns_zero(self):
        """Date invalide retourne 0 sans exception."""
        bonus = compute_freshness_bonus("not-a-date")
        assert bonus == 0

    def test_freshness_included_in_risk_score(self, engine):
        """La fraîcheur est incluse dans le risk_score final."""
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(hours=5)).isoformat()
        old = (now - timedelta(days=15)).isoformat()

        score_recent = engine.compute_risk_score(
            severity="HIGH", source_name="CISA KEV Catalog",
            published_iso=recent, exploit_available=True
        )
        score_old = engine.compute_risk_score(
            severity="HIGH", source_name="CISA KEV Catalog",
            published_iso=old, exploit_available=True
        )
        # L'article récent doit avoir un score plus élevé
        assert score_recent.total > score_old.total


# ---------------------------------------------------------------------------
# Tests : pondération source
# ---------------------------------------------------------------------------

class TestSourceReliability:
    def test_cisa_kev_has_max_reliability(self):
        """La source CISA KEV doit avoir la fiabilité maximale."""
        assert get_source_reliability("CISA KEV Catalog") == 1.0

    def test_unknown_source_gets_default(self):
        """Une source inconnue reçoit le coefficient par défaut."""
        r = get_source_reliability("Unknown Blog XYZ")
        assert r == 0.70

    def test_high_reliability_boosts_score(self, engine):
        """Une source fiable doit générer un score plus élevé."""
        now = datetime.now(timezone.utc).isoformat()
        score_trusted = engine.compute_risk_score(
            severity="HIGH", source_name="CISA KEV Catalog",
            published_iso=now
        )
        score_unknown = engine.compute_risk_score(
            severity="HIGH", source_name="UnknownBlog",
            published_iso=now
        )
        assert score_trusted.total >= score_unknown.total

    def test_custom_weights_override_defaults(self):
        """Les pondérations personnalisées écrasent les défauts."""
        custom = {"My Custom Source": 1.0}
        r = get_source_reliability("My Custom Source", custom)
        assert r == 1.0


# ---------------------------------------------------------------------------
# Tests : ScoreBreakdown
# ---------------------------------------------------------------------------

class TestScoreBreakdown:
    def test_breakdown_accumulates_components(self):
        """ScoreBreakdown accumule correctement les composantes."""
        bd = ScoreBreakdown()
        bd.add("base", 30).add("exploit", 15).add("freshness", 10)
        assert bd.total == 55
        assert len(bd.components) == 3

    def test_breakdown_cap_at_100(self):
        """Le score ne dépasse pas 100."""
        bd = ScoreBreakdown()
        bd.add("huge", 200).cap(100)
        assert bd.total == 100

    def test_breakdown_floor_at_zero(self):
        """Le score ne descend pas sous 0."""
        bd = ScoreBreakdown()
        bd.add("negative", -50).floor(0)
        assert bd.total == 0

    def test_breakdown_to_dict(self):
        """to_dict retourne le bon format."""
        bd = ScoreBreakdown()
        bd.add("source", 10)
        d = bd.to_dict()
        assert "total" in d
        assert "breakdown" in d
        assert d["breakdown"][0]["label"] == "source"
        assert d["breakdown"][0]["value"] == 10

    def test_breakdown_ignores_zero_values(self):
        """Les composantes à 0 ne sont pas incluses."""
        bd = ScoreBreakdown()
        bd.add("active", 10).add("empty", 0)
        assert len(bd.components) == 1
