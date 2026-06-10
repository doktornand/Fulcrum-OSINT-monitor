"""
tests/test_sqlite_store.py — Tests unitaires pour persistence/sqlite_store.py

Couvre :
  - Initialisation de la base
  - Upsert et existence d'articles
  - Requêtes avec filtres
  - Persistance IOCs
  - Risk evolution
  - Pruning
"""

import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from persistence.sqlite_store import SQLiteStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    """SQLiteStore en base temporaire (supprimée après chaque test)."""
    db_path = tmp_path / "test_fulcrum.db"
    s = SQLiteStore(str(db_path), retention_days=90)
    yield s
    s.close()


def _make_article(
    id_="art001",
    title="Test Article",
    source="Test Source",
    severity="HIGH",
    risk_score=70,
    strat_score=30,
    published=None,
    theatres=None,
    actors=None,
):
    """Factory pour créer des articles de test."""
    if published is None:
        published = datetime.now(timezone.utc).isoformat()
    return {
        "id": id_,
        "content_hash": f"hash_{id_}",
        "simhash": 12345678,
        "title": title,
        "source": source,
        "source_url": "https://example.com",
        "category": "Cyber",
        "published": published,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "risk_score": risk_score,
        "strat_score": strat_score,
        "theatres": theatres or [],
        "actors": actors or [],
        "cves": ["CVE-2024-1234"],
        "tags": ["test"],
        "risk_breakdown": {"total": risk_score, "breakdown": []},
        "strat_breakdown": {"total": strat_score, "breakdown": []},
        "summary": "Test summary",
        "confidence": 8,
        "domain": "cyber",
        "link": "https://example.com/article",
    }


# ---------------------------------------------------------------------------
# Tests : initialisation
# ---------------------------------------------------------------------------

class TestInitialization:
    def test_db_file_created(self, tmp_path):
        """Le fichier SQLite doit être créé à l'initialisation."""
        db_path = tmp_path / "init_test.db"
        store = SQLiteStore(str(db_path))
        store.close()
        assert db_path.exists()

    def test_tables_created(self, store):
        """Les tables requises doivent exister."""
        conn = store._get_conn()
        tables = [
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        assert "articles" in tables
        assert "iocs_extracted" in tables
        assert "correlations_detected" in tables
        assert "source_stats" in tables


# ---------------------------------------------------------------------------
# Tests : upsert et existence
# ---------------------------------------------------------------------------

class TestUpsertAndExists:
    def test_new_article_returns_true(self, store):
        """L'insertion d'un nouvel article retourne True."""
        art = _make_article()
        assert store.upsert_article(art) is True

    def test_existing_article_returns_false(self, store):
        """La mise à jour d'un article existant retourne False."""
        art = _make_article()
        store.upsert_article(art)
        assert store.upsert_article(art) is False

    def test_article_exists_after_insert(self, store):
        """article_exists retourne True après insertion."""
        art = _make_article(id_="check001")
        store.upsert_article(art)
        assert store.article_exists("check001") is True

    def test_article_not_exists_before_insert(self, store):
        """article_exists retourne False si l'article n'existe pas."""
        assert store.article_exists("nonexistent") is False


# ---------------------------------------------------------------------------
# Tests : requêtes
# ---------------------------------------------------------------------------

class TestQueryArticles:
    def test_query_by_severity(self, store):
        """Filtrer par sévérité retourne les bons articles."""
        store.upsert_article(_make_article(id_="a1", severity="CRITICAL", risk_score=90))
        store.upsert_article(_make_article(id_="a2", severity="HIGH", risk_score=70))
        store.upsert_article(_make_article(id_="a3", severity="INFO", risk_score=10))

        results = store.query_articles(severity="CRITICAL")
        assert len(results) == 1
        assert results[0]["severity"] == "CRITICAL"

    def test_query_by_min_score(self, store):
        """Filtrer par score minimum exclut les articles sous le seuil."""
        store.upsert_article(_make_article(id_="b1", risk_score=80))
        store.upsert_article(_make_article(id_="b2", risk_score=40))

        results = store.query_articles(min_risk_score=70)
        ids = [r["id"] for r in results]
        assert "b1" in ids
        assert "b2" not in ids

    def test_query_by_theatre(self, store):
        """Filtrer par théâtre retourne les articles correspondants."""
        store.upsert_article(_make_article(id_="c1", theatres=["ukraine"]))
        store.upsert_article(_make_article(id_="c2", theatres=["middle-east"]))

        results = store.query_articles(theatre="ukraine")
        ids = [r["id"] for r in results]
        assert "c1" in ids
        assert "c2" not in ids

    def test_query_returns_dict_with_deserialized_lists(self, store):
        """Les champs JSON doivent être désérialisés en listes Python."""
        store.upsert_article(_make_article(id_="d1", actors=["Russia", "Ukraine"]))
        results = store.query_articles()
        assert isinstance(results[0]["actors"], list)
        assert isinstance(results[0]["theatres"], list)


# ---------------------------------------------------------------------------
# Tests : IOCs
# ---------------------------------------------------------------------------

class TestIOCPersistence:
    def test_iocs_saved_and_searchable(self, store):
        """Les IOCs insérés doivent être trouvables par recherche."""
        store.upsert_article(_make_article(id_="ioc001"))
        store.upsert_iocs("ioc001", {"ipv4": ["185.220.101.42"], "domain": ["evil.example.com"]})

        results = store.search_ioc("185.220.101.42")
        assert len(results) >= 1
        assert results[0]["ioc_value"] == "185.220.101.42"

    def test_duplicate_iocs_not_doubled(self, store):
        """Les IOCs en doublon ne sont pas dupliqués en base."""
        store.upsert_article(_make_article(id_="ioc002"))
        store.upsert_iocs("ioc002", {"ipv4": ["1.2.3.4"]})
        store.upsert_iocs("ioc002", {"ipv4": ["1.2.3.4"]})  # doublon

        results = store.search_ioc("1.2.3.4")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Tests : Risk evolution
# ---------------------------------------------------------------------------

class TestRiskEvolution:
    def test_risk_evolution_returns_7d_and_30d(self, store):
        """get_risk_evolution retourne les deux périodes."""
        store.upsert_article(_make_article(id_="ev001", risk_score=75))
        evolution = store.get_risk_evolution(days=30)
        assert "7d" in evolution
        assert "30d" in evolution
        assert "generated_at" in evolution

    def test_risk_evolution_counts_articles(self, store):
        """Le total d'articles est bien compté."""
        store.upsert_article(_make_article(id_="ev002"))
        store.upsert_article(_make_article(id_="ev003"))
        evolution = store.get_risk_evolution(days=30)
        assert evolution["30d"]["total"] >= 2


# ---------------------------------------------------------------------------
# Tests : pruning
# ---------------------------------------------------------------------------

class TestPruning:
    def test_old_articles_pruned(self, store):
        """Les articles plus anciens que retention_days doivent être supprimés."""
        old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        store.upsert_article(_make_article(id_="old001", published=old_date))
        assert store.article_exists("old001") is True

        count = store.prune_old_articles()
        assert count >= 1
        assert store.article_exists("old001") is False

    def test_recent_articles_not_pruned(self, store):
        """Les articles récents ne doivent pas être supprimés."""
        store.upsert_article(_make_article(id_="recent001"))
        store.prune_old_articles()
        assert store.article_exists("recent001") is True
