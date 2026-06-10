"""
analyzers/correlator.py — Corrélation et déduplication fuzzy (SimHash/MinHash)

Remplace le hash MD5 simple du monolithe par une correspondance de similarité
basée sur SimHash (locality-sensitive hashing) avec seuil configurable.

Fonctionnalités :
  - SimHash 64-bit sur titre + résumé (sans dépendance ML)
  - Déduplication fuzzy : seuil similarité configurable (défaut 0.85)
  - Détection de clusters : même acteur + même théâtre + fenêtre 72h
  - Timeline chronologique par théâtre/acteur
  - Mode --since last-run via fichier .fulcrum_last_run

Google-style docstrings. Aucune dépendance IA/LLM/NLP.
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# SimHash 64-bit
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> List[str]:
    """Tokenise un texte en n-grams de caractères (3-grams).

    L'approche n-gram est plus robuste que les mots pour les titres courts
    et les variantes orthographiques mineures.

    Args:
        text: Texte normalisé.

    Returns:
        Liste de n-grams.
    """
    normalized = re.sub(r"[^a-z0-9\s]", "", text.lower())
    words = normalized.split()
    tokens = []
    for word in words:
        tokens.append(word)
        # 3-grams de caractères
        for i in range(len(word) - 2):
            tokens.append(word[i : i + 3])
    return tokens


def _hash_token(token: str) -> int:
    """Hash d'un token sur 64 bits.

    Args:
        token: Token à hasher.

    Returns:
        Entier 64 bits.
    """
    return int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16) & 0xFFFFFFFFFFFFFFFF


def compute_simhash(text: str) -> int:
    """Calcule le SimHash 64-bit d'un texte.

    Algorithme :
      1. Tokenise le texte
      2. Pour chaque token, hash 64-bit → vecteur de bits
      3. Accumule un vecteur de sommes pondérées
      4. Chaque bit du SimHash = signe de la somme correspondante

    Args:
        text: Texte à hasher.

    Returns:
        Entier 64-bit SimHash.

    Example:
        >>> h1 = compute_simhash("RCE vulnerability in OpenSSL CVE-2024-1234")
        >>> h2 = compute_simhash("OpenSSL CVE-2024-1234 remote code execution")
        >>> hamming_distance(h1, h2) < 8  # articles similaires
        True
    """
    tokens = _tokenize(text)
    if not tokens:
        return 0

    vector = [0] * 64

    for token in tokens:
        h = _hash_token(token)
        for i in range(64):
            if (h >> i) & 1:
                vector[i] += 1
            else:
                vector[i] -= 1

    simhash = 0
    for i in range(64):
        if vector[i] > 0:
            simhash |= 1 << i

    return simhash


def hamming_distance(h1: int, h2: int) -> int:
    """Calcule la distance de Hamming entre deux SimHashes.

    Args:
        h1: Premier SimHash 64-bit.
        h2: Deuxième SimHash 64-bit.

    Returns:
        Nombre de bits différents (0 = identique, 64 = opposé).
    """
    xor = h1 ^ h2
    count = 0
    while xor:
        count += xor & 1
        xor >>= 1
    return count


def similarity(h1: int, h2: int) -> float:
    """Calcule la similarité normalisée entre deux SimHashes.

    Args:
        h1: Premier SimHash 64-bit.
        h2: Deuxième SimHash 64-bit.

    Returns:
        Score entre 0.0 (opposés) et 1.0 (identiques).
    """
    return 1.0 - hamming_distance(h1, h2) / 64.0


# ---------------------------------------------------------------------------
# Déduplicateur fuzzy
# ---------------------------------------------------------------------------

class FuzzyDeduplicator:
    """Déduplication d'articles par similarité SimHash.

    Args:
        threshold: Seuil de similarité au-delà duquel deux articles
            sont considérés comme doublons (défaut 0.85).

    Example:
        >>> dedup = FuzzyDeduplicator(threshold=0.85)
        >>> unique = dedup.deduplicate(articles)
    """

    def __init__(self, threshold: float = 0.85) -> None:
        self.threshold = threshold
        self._seen: List[Tuple[int, str]] = []  # (simhash, article_id)

    def is_duplicate(self, simhash: int, article_id: str) -> bool:
        """Vérifie si un article est un doublon fuzzy d'un article déjà vu.

        Args:
            simhash: SimHash de l'article candidat.
            article_id: Identifiant de l'article.

        Returns:
            True si un article similaire a déjà été traité.
        """
        for seen_hash, seen_id in self._seen:
            if seen_id == article_id:
                continue
            if similarity(simhash, seen_hash) >= self.threshold:
                return True
        return False

    def add(self, simhash: int, article_id: str) -> None:
        """Enregistre un article comme vu.

        Args:
            simhash: SimHash de l'article.
            article_id: Identifiant de l'article.
        """
        self._seen.append((simhash, article_id))

    def deduplicate(self, articles: list) -> list:
        """Filtre une liste d'articles en supprimant les doublons fuzzy.

        Les articles sont traités dans l'ordre : le premier occurrence
        est conservée, les suivantes supprimées si trop similaires.

        Args:
            articles: Liste d'objets avec attributs 'title', 'summary', 'id'.

        Returns:
            Liste filtrée sans doublons.
        """
        unique = []
        for art in articles:
            text = f"{getattr(art, 'title', '')} {getattr(art, 'summary', '')}"
            sh = compute_simhash(text)
            art_id = getattr(art, "id", str(id(art)))

            if not self.is_duplicate(sh, art_id):
                self.add(sh, art_id)
                unique.append(art)

        return unique


# ---------------------------------------------------------------------------
# Détecteur de clusters
# ---------------------------------------------------------------------------

class ClusterDetector:
    """Détecte les clusters d'articles liés à un même incident.

    Un cluster est défini par :
      - Même acteur étatique principal ET
      - Même théâtre géographique ET
      - Fenêtre temporelle ≤ 72h

    Args:
        window_hours: Fenêtre temporelle pour le clustering (défaut 72h).

    Example:
        >>> detector = ClusterDetector(window_hours=72)
        >>> clusters = detector.detect(articles)
        >>> for cluster_id, arts in clusters.items():
        ...     print(f"Cluster {cluster_id}: {len(arts)} articles")
    """

    def __init__(self, window_hours: int = 72) -> None:
        self.window = timedelta(hours=window_hours)

    def detect(self, articles: list) -> Dict[str, list]:
        """Regroupe les articles en clusters d'incidents.

        Args:
            articles: Liste d'articles avec attributs 'actors', 'theatres', 'published'.

        Returns:
            Dict mapping cluster_id → liste d'articles.
        """
        clusters: Dict[str, list] = {}

        for art in articles:
            cluster_id = self._find_cluster(art, clusters)
            if cluster_id:
                clusters[cluster_id].append(art)
            else:
                # Créer un nouveau cluster
                actors = getattr(art, "actors", [])
                theatres = getattr(art, "theatres", [])
                if actors and theatres:
                    key = f"{actors[0].lower()}|{theatres[0].lower()}"
                    clusters[key] = [art]

        return {k: v for k, v in clusters.items() if len(v) > 1}

    def _find_cluster(self, article, clusters: Dict[str, list]) -> Optional[str]:
        """Recherche un cluster existant compatible avec l'article.

        Args:
            article: Article à classifier.
            clusters: Clusters existants.

        Returns:
            Clé du cluster compatible ou None.
        """
        art_actors = set(a.lower() for a in getattr(article, "actors", []))
        art_theatres = set(t.lower() for t in getattr(article, "theatres", []))
        art_pub = self._parse_date(getattr(article, "published", ""))

        if not art_actors or not art_theatres or art_pub is None:
            return None

        for cluster_id, cluster_arts in clusters.items():
            # Vérifier chevauchement acteurs et théâtres
            cluster_actors = set()
            cluster_theatres = set()
            for a in cluster_arts:
                cluster_actors.update(x.lower() for x in getattr(a, "actors", []))
                cluster_theatres.update(x.lower() for x in getattr(a, "theatres", []))

            if not (art_actors & cluster_actors) or not (art_theatres & cluster_theatres):
                continue

            # Vérifier fenêtre temporelle
            for existing_art in cluster_arts:
                existing_pub = self._parse_date(getattr(existing_art, "published", ""))
                if existing_pub and abs((art_pub - existing_pub).total_seconds()) <= self.window.total_seconds():
                    return cluster_id

        return None

    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """Parse une date ISO 8601 en datetime.

        Args:
            date_str: Date en format ISO 8601.

        Returns:
            Datetime ou None si invalide.
        """
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Timeline par théâtre
# ---------------------------------------------------------------------------

def build_timeline(articles: list) -> Dict[str, list]:
    """Construit une timeline chronologique des articles par théâtre.

    Args:
        articles: Liste d'articles triés ou non chronologiquement.

    Returns:
        Dict mapping théâtre → liste d'articles triés par date décroissante.
    """
    timeline: Dict[str, list] = {}

    for art in articles:
        for theatre in getattr(art, "theatres", []):
            if theatre not in timeline:
                timeline[theatre] = []
            timeline[theatre].append(art)

    # Tri chronologique décroissant par théâtre
    for theatre in timeline:
        timeline[theatre].sort(
            key=lambda a: getattr(a, "published", ""),
            reverse=True,
        )

    return timeline


# ---------------------------------------------------------------------------
# Mode --since last-run
# ---------------------------------------------------------------------------

LAST_RUN_FILE = Path(".fulcrum_last_run")


def get_last_run_timestamp() -> Optional[datetime]:
    """Lit le timestamp du dernier run depuis .fulcrum_last_run.

    Returns:
        Datetime du dernier run ou None si fichier absent.
    """
    if not LAST_RUN_FILE.exists():
        return None
    try:
        ts = float(LAST_RUN_FILE.read_text().strip())
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError):
        return None


def save_last_run_timestamp() -> None:
    """Enregistre le timestamp du run courant dans .fulcrum_last_run."""
    LAST_RUN_FILE.write_text(str(time.time()))


def filter_since_last_run(articles: list) -> list:
    """Filtre les articles publiés depuis le dernier run.

    Args:
        articles: Liste complète d'articles.

    Returns:
        Articles publiés après le dernier run, ou tous si premier run.
    """
    last_run = get_last_run_timestamp()
    if last_run is None:
        return articles

    result = []
    for art in articles:
        pub_str = getattr(art, "published", "")
        try:
            pub = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            if pub > last_run:
                result.append(art)
        except (ValueError, TypeError):
            result.append(art)  # inclure si date invalide

    return result
