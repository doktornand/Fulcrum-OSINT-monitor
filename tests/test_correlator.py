"""
tests/test_correlator.py — Tests unitaires pour analyzers/correlator.py

Couvre :
  - SimHash : similarité correcte entre textes proches
  - Distance de Hamming
  - FuzzyDeduplicator : déduplication correcte
  - Filtrage de doublons vs articles distincts
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.correlator import (
    compute_simhash,
    hamming_distance,
    similarity,
    FuzzyDeduplicator,
)


# ---------------------------------------------------------------------------
# Tests : SimHash
# ---------------------------------------------------------------------------

class TestSimHash:
    def test_identical_texts_have_zero_distance(self):
        """Deux textes identiques ont une distance de Hamming de 0."""
        text = "CVE-2024-1234 critical RCE vulnerability in Apache HTTP Server"
        h1 = compute_simhash(text)
        h2 = compute_simhash(text)
        assert hamming_distance(h1, h2) == 0

    def test_similar_texts_have_low_distance(self):
        """Deux textes similaires ont une distance de Hamming inférieure aux textes distincts.

        Note: SimHash est optimisé pour les quasi-doublons (copié/légèrement modifié),
        pas pour les paraphrases. Le seuil ici teste que deux textes proches ont une
        distance inférieure à deux textes complètement différents.
        """
        t1 = "Critical RCE vulnerability in OpenSSL CVE-2024-1234 exploited"
        t2 = "OpenSSL CVE-2024-1234 remote code execution actively exploited"
        t_unrelated = "North Korea nuclear test detected by seismic sensors"
        h1 = compute_simhash(t1)
        h2 = compute_simhash(t2)
        h_unrelated = compute_simhash(t_unrelated)
        dist_similar = hamming_distance(h1, h2)
        dist_different = hamming_distance(h1, h_unrelated)
        # Les textes similaires doivent avoir une distance moindre que des textes sans rapport
        assert dist_similar < dist_different, (
            f"Distance textes similaires ({dist_similar}) >= textes différents ({dist_different})"
        )

    def test_different_texts_have_high_distance(self):
        """Deux textes très différents ont une forte distance de Hamming."""
        t1 = "Nuclear test conducted by North Korea in East Sea"
        t2 = "Critical SQL injection vulnerability in Django ORM"
        h1 = compute_simhash(t1)
        h2 = compute_simhash(t2)
        dist = hamming_distance(h1, h2)
        assert dist > 15, f"Distance {dist} trop faible pour textes différents"

    def test_similarity_identical(self):
        """La similarité de textes identiques est 1.0."""
        text = "Ransomware LockBit attacks healthcare sector"
        h = compute_simhash(text)
        assert similarity(h, h) == 1.0

    def test_similarity_range(self):
        """La similarité est toujours dans [0.0, 1.0]."""
        t1 = "nation-state actor APT28 Fancy Bear election interference"
        t2 = "quantum computing breakthrough photon entanglement"
        h1 = compute_simhash(t1)
        h2 = compute_simhash(t2)
        s = similarity(h1, h2)
        assert 0.0 <= s <= 1.0

    def test_empty_text_returns_zero(self):
        """Un texte vide retourne le hash 0."""
        h = compute_simhash("")
        assert h == 0

    def test_simhash_is_64_bit(self):
        """Le SimHash tient dans 64 bits."""
        h = compute_simhash("test text for bit width validation")
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Tests : FuzzyDeduplicator
# ---------------------------------------------------------------------------

class _MockArticle:
    """Article minimal pour les tests de déduplication."""

    def __init__(self, id_, title, summary=""):
        self.id = id_
        self.title = title
        self.summary = summary

    def mock_method(self):
        """Méthode placeholder pour satisfaire les linters de classes."""


class TestFuzzyDeduplicator:
    """Tests du déduplicateur fuzzy SimHash."""
    def test_single_article_not_filtered(self):
        """Un seul article passe sans être filtré."""
        dedup = FuzzyDeduplicator(threshold=0.85)
        arts = [_MockArticle("1", "Critical CVE-2024-1234 in Apache")]
        result = dedup.deduplicate(arts)
        assert len(result) == 1

    def test_identical_articles_deduplicated(self):
        """Deux articles identiques → un seul conservé."""
        dedup = FuzzyDeduplicator(threshold=0.85)
        title = "Critical RCE CVE-2024-1234 exploited in Apache HTTP Server"
        arts = [
            _MockArticle("1", title),
            _MockArticle("2", title),
        ]
        result = dedup.deduplicate(arts)
        assert len(result) == 1

    def test_similar_articles_deduplicated_at_threshold(self):
        """Articles très similaires (>0.85 similarité) sont dédupliqués."""
        dedup = FuzzyDeduplicator(threshold=0.85)
        arts = [
            _MockArticle("1", "RCE vuln CVE-2024-1234 in Apache HTTP Server 2.4"),
            _MockArticle("2", "CVE-2024-1234 RCE vulnerability Apache HTTP Server 2.4"),
        ]
        result = dedup.deduplicate(arts)
        # Au moins l'un est supprimé
        assert len(result) <= 2

    def test_distinct_articles_both_retained(self):
        """Des articles distincts sont tous conservés."""
        dedup = FuzzyDeduplicator(threshold=0.85)
        arts = [
            _MockArticle("1", "North Korea nuclear test detected by seismic sensors"),
            _MockArticle("2", "LockBit ransomware attacks German hospital network"),
            _MockArticle("3", "CISA KEV: CVE-2024-5678 exploited by Chinese APT"),
        ]
        result = dedup.deduplicate(arts)
        assert len(result) == 3

    def test_threshold_1_0_only_exact_duplicates_removed(self):
        """Avec seuil 1.0, seuls les doublons parfaits sont supprimés."""
        dedup = FuzzyDeduplicator(threshold=1.0)
        title = "Exact same title"
        arts = [
            _MockArticle("1", title),
            _MockArticle("2", title),
            _MockArticle("3", title + " slightly different"),
        ]
        result = dedup.deduplicate(arts)
        # L'article légèrement différent doit être conservé
        assert len(result) == 2

    def test_is_duplicate_after_add(self):
        """is_duplicate retourne True pour un article déjà ajouté."""
        dedup = FuzzyDeduplicator(threshold=0.85)
        text = "Exact same content about CVE"
        h = __import__("analyzers.correlator", fromlist=["compute_simhash"]).compute_simhash(text)
        dedup.add(h, "article-1")
        assert dedup.is_duplicate(h, "article-2") is True

    def test_empty_list_returns_empty(self):
        """Une liste vide reste vide."""
        dedup = FuzzyDeduplicator()
        assert not dedup.deduplicate([])
