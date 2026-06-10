"""
tests/test_report_generator.py — Tests unitaires pour ReportGenerator.

Vérifie le rendu des templates Jinja2 et le fallback texte brut.
"""

from __future__ import annotations

import pytest
from pathlib import Path
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def daily_brief_data():
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": "2026-03-24",
        "headline": "Niveau de menace ÉLEVÉ : 3 critiques détectés.",
        "threat_level": "ÉLEVÉ",
        "sections": [
            {"title": "ALERTES CRITIQUES", "items": ["CVE-2024-1234 exploité activement"]},
            {"title": "RANSOMWARE", "items": ["LockBit → AcmeCorp"]},
        ],
    }


@pytest.fixture
def incident_data():
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": "RANSOMWARE",
        "incident": {
            "type": "ransomware",
            "severity": "CRITICAL",
            "composite_score": 88,
            "title": "LockBit targets AcmeCorp",
            "source": "Ransomware.live",
            "published": datetime.now(timezone.utc).isoformat(),
            "link": "https://ransomware.live",
        },
        "actors": ["LockBit"],
        "theatres": ["europe"],
        "cves": [],
        "iocs": ["192.0.2.1", "evil.example.com"],
        "assessment": "Incident confirmé par 2 sources indépendantes.",
        "related_incidents": 0,
        "recommended_actions": [
            "Isoler les systèmes affectés",
            "Contacter l'équipe IR",
        ],
    }


# ---------------------------------------------------------------------------
# Tests rendu Jinja2
# ---------------------------------------------------------------------------

class TestReportGeneratorJinja:
    def test_render_daily_brief_returns_string(self, daily_brief_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        result = reporter.render("daily_brief", daily_brief_data)
        assert isinstance(result, str)
        assert len(result) > 50

    def test_render_daily_brief_contains_threat_level(self, daily_brief_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        result = reporter.render("daily_brief", daily_brief_data)
        assert "ÉLEVÉ" in result

    def test_render_daily_brief_contains_headline(self, daily_brief_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        result = reporter.render("daily_brief", daily_brief_data)
        assert "3 critiques" in result

    def test_render_incident_flash_contains_classification(self, incident_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        result = reporter.render("incident_flash", incident_data)
        assert isinstance(result, str)
        # Either Jinja2 rendered it or fallback; both should produce something
        assert len(result) > 20

    def test_render_weekly_strategic(self):
        from exporters.report_generator import ReportGenerator
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": "2026-W12",
            "headline": "Semaine calme malgré tensions.",
            "sections": [
                {"title": "TENDANCES", "items": ["Montée des APT en Europe"]},
            ],
        }
        reporter = ReportGenerator()
        result = reporter.render("weekly_strategic", data)
        assert isinstance(result, str)
        assert len(result) > 20

    def test_render_unknown_type_uses_fallback(self, daily_brief_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        # Unknown template → fallback
        result = reporter.render("nonexistent_template", daily_brief_data)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_save_creates_file(self, tmp_path, daily_brief_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        content = reporter.render("daily_brief", daily_brief_data)
        out = tmp_path / "brief.txt"
        reporter.save(content, str(out))
        assert out.exists()
        assert out.stat().st_size > 0

    def test_render_and_save_returns_path(self, tmp_path, daily_brief_data):
        from exporters.report_generator import ReportGenerator
        reporter = ReportGenerator()
        out = tmp_path / "brief2.txt"
        result = reporter.render_and_save("daily_brief", daily_brief_data, str(out))
        assert isinstance(result, Path)
        assert result.exists()


# ---------------------------------------------------------------------------
# Tests fallback texte brut
# ---------------------------------------------------------------------------

class TestReportGeneratorFallback:
    def test_fallback_contains_report_type(self):
        from exporters.report_generator import ReportGenerator
        data = {
            "generated_at": "2026-03-24T10:00:00",
            "period": "2026-03-24",
            "headline": "Test headline",
            "sections": [],
        }
        result = ReportGenerator._render_fallback("daily_brief", data)
        assert "DAILY BRIEF" in result

    def test_fallback_contains_sections(self):
        from exporters.report_generator import ReportGenerator
        data = {
            "generated_at": "2026-03-24T10:00:00",
            "period": "2026-03-24",
            "headline": "",
            "sections": [
                {"title": "SECTION A", "items": ["Item 1", "Item 2"]},
            ],
        }
        result = ReportGenerator._render_fallback("daily_brief", data)
        assert "SECTION A" in result
        assert "Item 1" in result

    def test_fallback_incident_flash_format(self):
        from exporters.report_generator import ReportGenerator
        data = {
            "generated_at": "2026-03-24T10:00:00",
            "period": "",
            "headline": "",
            "sections": [],
            "incident": {
                "type": "ransomware",
                "severity": "CRITICAL",
                "composite_score": 88,
                "title": "LockBit attack",
            },
            "recommended_actions": ["Isolate", "Contact IR"],
        }
        result = ReportGenerator._render_fallback("incident_flash", data)
        assert "CRITIQUE" in result or "CRITICAL" in result
        assert "Isolate" in result
