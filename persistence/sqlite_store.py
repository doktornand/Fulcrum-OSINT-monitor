"""
persistence/sqlite_store.py — Persistance SQLite pour FULCRUM

Tables :
  - articles       : articles traités (hash, titre, source, date, scores, théâtre, acteurs)
  - iocs_extracted : IOCs extraits par article
  - correlations   : clusters d'incidents détectés
  - source_stats   : fiabilité historique des sources

Fonctionnalités :
  - Indexation sur date, théâtre, acteur, simhash
  - Pruning automatique (90j conservation, archivage 1an)
  - Requêtes par théâtre, acteur, sévérité, plage temporelle
  - Risk evolution : comparaison volume/sévérité sur 7j/30j

Google-style docstrings. Dépendance : sqlite3 (stdlib).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("FULCRUM.sqlite")

# ---------------------------------------------------------------------------
# Schéma SQL
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS articles (
    id              TEXT PRIMARY KEY,
    content_hash    TEXT NOT NULL,
    simhash         INTEGER,
    title           TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_url      TEXT,
    category        TEXT,
    published       TEXT,
    processed_at    TEXT,
    severity        TEXT,
    risk_score      INTEGER DEFAULT 0,
    strat_score     INTEGER DEFAULT 0,
    theatres        TEXT,   -- JSON list
    actors          TEXT,   -- JSON list
    cves            TEXT,   -- JSON list
    tags            TEXT,   -- JSON list
    risk_breakdown  TEXT,   -- JSON breakdown dict
    strat_breakdown TEXT,   -- JSON breakdown dict
    raw_content     TEXT,
    confidence      INTEGER DEFAULT 5,
    domain          TEXT,
    link            TEXT
);

CREATE INDEX IF NOT EXISTS idx_articles_published   ON articles(published);
CREATE INDEX IF NOT EXISTS idx_articles_severity    ON articles(severity);
CREATE INDEX IF NOT EXISTS idx_articles_source      ON articles(source);
CREATE INDEX IF NOT EXISTS idx_articles_simhash     ON articles(simhash);
CREATE INDEX IF NOT EXISTS idx_articles_risk_score  ON articles(risk_score DESC);

CREATE TABLE IF NOT EXISTS iocs_extracted (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id  TEXT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    ioc_type    TEXT NOT NULL,    -- ipv4, sha256, domain…
    ioc_value   TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    UNIQUE(article_id, ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs_extracted(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs_extracted(ioc_type);

CREATE TABLE IF NOT EXISTS correlations_detected (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id      TEXT NOT NULL,
    article_ids     TEXT NOT NULL,  -- JSON list
    theatre         TEXT,
    actors          TEXT,           -- JSON list
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    article_count   INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_correlations_cluster ON correlations_detected(cluster_id);
CREATE INDEX IF NOT EXISTS idx_correlations_theatre ON correlations_detected(theatre);

CREATE TABLE IF NOT EXISTS source_stats (
    source          TEXT PRIMARY KEY,
    total_articles  INTEGER DEFAULT 0,
    avg_risk_score  REAL DEFAULT 0,
    avg_strat_score REAL DEFAULT 0,
    last_seen       TEXT,
    reliability     REAL DEFAULT 0.7
);

CREATE TABLE IF NOT EXISTS run_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at      TEXT NOT NULL,
    duration_s  REAL,
    articles_fetched  INTEGER DEFAULT 0,
    articles_new      INTEGER DEFAULT 0,
    articles_deduped  INTEGER DEFAULT 0,
    mode        TEXT
);
"""

# ---------------------------------------------------------------------------
# SQLiteStore
# ---------------------------------------------------------------------------

class SQLiteStore:
    """Store de persistance SQLite pour FULCRUM.

    Args:
        db_path: Chemin vers le fichier SQLite.
        retention_days: Nombre de jours de rétention active (défaut 90).
        archive_days: Nombre de jours avant archivage/compression (défaut 365).

    Example:
        >>> store = SQLiteStore("fulcrum.db")
        >>> store.upsert_article(article_dict)
        >>> articles = store.query_articles(theatre="ukraine", days=7)
    """

    def __init__(
        self,
        db_path: str = "fulcrum.db",
        retention_days: int = 90,
        archive_days: int = 365,
    ) -> None:
        self.db_path = Path(db_path)
        self.retention_days = retention_days
        self.archive_days = archive_days
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Connexion
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Retourne la connexion SQLite (lazy init, thread-safe).

        Returns:
            Connexion SQLite configurée.
        """
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def _init_db(self) -> None:
        """Initialise le schéma de base de données.

        Crée les tables et index si absents.
        """
        conn = self._get_conn()
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
        logger.info(f"SQLite initialisé : {self.db_path}")

    def close(self) -> None:
        """Ferme la connexion SQLite."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Simhash helper — CORRECTION CRITIQUE
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_simhash(raw_simhash: Any) -> Optional[int]:
        """Convertit un simhash brut en entier sûr pour SQLite INTEGER (64-bit signé).

        SQLite INTEGER = 64-bit signed: [-9223372036854775808, 9223372036854775807]
        On applique un masque 63-bit pour garantir la compatibilité.

        Args:
            raw_simhash: Valeur brute du simhash (int, str, None).

        Returns:
            Entier signé 64-bit ou None.
        """
        if raw_simhash is None:
            return None
        try:
            val = int(raw_simhash)
        except (TypeError, ValueError):
            return None
        # Masque 63-bit pour rester dans les limites d'un INTEGER signé 64-bit SQLite
        return val & 0x7FFFFFFFFFFFFFFF

    # ------------------------------------------------------------------
    # Articles
    # ------------------------------------------------------------------

    def upsert_article(self, article: Dict[str, Any]) -> bool:
        """Insère ou met à jour un article.

        Args:
            article: Dict avec les champs de l'article.

        Returns:
            True si nouvel article, False si mise à jour.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        is_new = not self.article_exists(article.get("id", ""))

        # --- CORRECTION : sécurisation du simhash sur 63 bits (signed 64-bit SQLite) ---
        safe_simhash = self._safe_simhash(article.get("simhash"))
        # -------------------------------------------------------------------------------

        conn.execute(
            """
            INSERT OR REPLACE INTO articles
                (id, content_hash, simhash, title, source, source_url, category,
                 published, processed_at, severity, risk_score, strat_score,
                 theatres, actors, cves, tags, risk_breakdown, strat_breakdown,
                 raw_content, confidence, domain, link)
            VALUES
                (:id, :content_hash, :simhash, :title, :source, :source_url, :category,
                 :published, :processed_at, :severity, :risk_score, :strat_score,
                 :theatres, :actors, :cves, :tags, :risk_breakdown, :strat_breakdown,
                 :raw_content, :confidence, :domain, :link)
            """,
            {
                "id": article.get("id", ""),
                "content_hash": article.get("content_hash", ""),
                "simhash": safe_simhash,
                "title": article.get("title", "")[:500],
                "source": article.get("source", ""),
                "source_url": article.get("source_url", ""),
                "category": article.get("category", ""),
                "published": article.get("published", now),
                "processed_at": article.get("processed_at", now),
                "severity": article.get("severity", "INFO"),
                "risk_score": article.get("risk_score", 0),
                "strat_score": article.get("strat_score", 0),
                "theatres": json.dumps(article.get("theatres", [])),
                "actors": json.dumps(article.get("actors", [])),
                "cves": json.dumps(article.get("cves", [])),
                "tags": json.dumps(article.get("tags", [])),
                "risk_breakdown": json.dumps(article.get("risk_score_breakdown", {})),
                "strat_breakdown": json.dumps(article.get("strat_score_breakdown", {})),
                "raw_content": (article.get("summary", "") or "")[:2000],
                "confidence": article.get("confidence", 5),
                "domain": article.get("domain", ""),
                "link": article.get("link", ""),
            },
        )
        conn.commit()
        return is_new

    def article_exists(self, article_id: str) -> bool:
        """Vérifie si un article existe déjà.

        Args:
            article_id: Identifiant de l'article.

        Returns:
            True si l'article est déjà en base.
        """
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM articles WHERE id = ?", (article_id,)
        ).fetchone()
        return row is not None

    def get_recent_simhashes(self, days: int = 30) -> List[Tuple[int, str]]:
        """Retourne les SimHashes des articles récents pour la déduplication.

        Args:
            days: Fenêtre temporelle en jours.

        Returns:
            Liste de (simhash, article_id).
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT simhash, id FROM articles WHERE published >= ? AND simhash IS NOT NULL",
            (since,),
        ).fetchall()
        return [(row["simhash"], row["id"]) for row in rows]

    # ------------------------------------------------------------------
    # Requêtes analytiques
    # ------------------------------------------------------------------

    def query_articles(
        self,
        theatre: Optional[str] = None,
        actor: Optional[str] = None,
        severity: Optional[str] = None,
        days: int = 30,
        limit: int = 100,
        min_risk_score: int = 0,
    ) -> List[Dict[str, Any]]:
        """Requête flexible d'articles avec filtres multiples.

        Args:
            theatre: Filtre par théâtre géographique.
            actor: Filtre par acteur étatique.
            severity: Filtre par sévérité (CRITICAL, HIGH…).
            days: Fenêtre temporelle en jours.
            limit: Nombre maximum de résultats.
            min_risk_score: Score de risque minimum.

        Returns:
            Liste de dicts articles.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conditions = ["published >= ?", "risk_score >= ?"]
        params: List[Any] = [since, min_risk_score]

        if theatre:
            conditions.append("theatres LIKE ?")
            params.append(f"%{theatre}%")

        if actor:
            conditions.append("actors LIKE ?")
            params.append(f"%{actor}%")

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        where = " AND ".join(conditions)
        params.append(limit)

        conn = self._get_conn()
        rows = conn.execute(
            f"""
            SELECT * FROM articles
            WHERE {where}
            ORDER BY risk_score DESC, published DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def get_risk_evolution(self, days: int = 30) -> Dict[str, Any]:
        """Calcule l'évolution du risque sur une période.

        Args:
            days: Nombre de jours à analyser.

        Returns:
            Dict avec statistiques comparatives 7j vs 30j.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc)

        def _stats_for_period(d: int) -> Dict[str, Any]:
            since = (now - timedelta(days=d)).isoformat()
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    AVG(risk_score) as avg_risk,
                    AVG(strat_score) as avg_strat,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
                FROM articles WHERE published >= ?
                """,
                (since,),
            ).fetchone()
            return dict(row) if row else {}

        return {
            "7d": _stats_for_period(7),
            "30d": _stats_for_period(days),
            "generated_at": now.isoformat(),
        }

    def get_top_sources(self, days: int = 7, limit: int = 20) -> List[Dict[str, Any]]:
        """Retourne les sources les plus actives.

        Args:
            days: Fenêtre temporelle.
            limit: Nombre de sources à retourner.

        Returns:
            Liste de dicts source avec compteurs et scores moyens.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT source, COUNT(*) as count,
                   AVG(risk_score) as avg_risk, MAX(risk_score) as max_risk
            FROM articles
            WHERE published >= ?
            GROUP BY source
            ORDER BY count DESC
            LIMIT ?
            """,
            (since, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def upsert_iocs(self, article_id: str, iocs: Dict[str, List[str]]) -> None:
        """Persiste les IOCs extraits d'un article.

        Args:
            article_id: Identifiant de l'article source.
            iocs: Dict {type: [valeurs]}.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        for ioc_type, values in iocs.items():
            for value in values:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO iocs_extracted
                            (article_id, ioc_type, ioc_value, first_seen)
                        VALUES (?, ?, ?, ?)
                        """,
                        (article_id, ioc_type, value, now),
                    )
                except sqlite3.IntegrityError:
                    pass
        conn.commit()

    def search_ioc(self, value: str) -> List[Dict[str, Any]]:
        """Recherche des articles contenant un IOC spécifique.

        Args:
            value: Valeur IOC à rechercher (IP, hash, domaine…).

        Returns:
            Liste de dicts avec contexte de l'IOC.
        """
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT i.ioc_type, i.ioc_value, i.first_seen,
                   a.title, a.source, a.published, a.link
            FROM iocs_extracted i
            JOIN articles a ON a.id = i.article_id
            WHERE i.ioc_value LIKE ?
            ORDER BY a.published DESC
            LIMIT 20
            """,
            (f"%{value}%",),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Corrélations
    # ------------------------------------------------------------------

    def save_cluster(
        self,
        cluster_id: str,
        article_ids: List[str],
        theatre: str,
        actors: List[str],
    ) -> None:
        """Enregistre un cluster d'incidents corrélés.

        Args:
            cluster_id: Identifiant unique du cluster.
            article_ids: Liste des articles du cluster.
            theatre: Théâtre géographique commun.
            actors: Acteurs communs.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO correlations_detected
                (cluster_id, article_ids, theatre, actors, first_seen, last_seen, article_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cluster_id,
                json.dumps(article_ids),
                theatre,
                json.dumps(actors),
                now,
                now,
                len(article_ids),
            ),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Source stats
    # ------------------------------------------------------------------

    def update_source_stats(self, source: str, risk_score: int, strat_score: int) -> None:
        """Met à jour les statistiques d'une source.

        Args:
            source: Nom de la source.
            risk_score: Score de risque du dernier article.
            strat_score: Score stratégique du dernier article.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO source_stats (source, total_articles, avg_risk_score, avg_strat_score, last_seen)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                total_articles  = total_articles + 1,
                avg_risk_score  = (avg_risk_score * total_articles + ?) / (total_articles + 1),
                avg_strat_score = (avg_strat_score * total_articles + ?) / (total_articles + 1),
                last_seen       = ?
            """,
            (source, risk_score, strat_score, now, risk_score, strat_score, now),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Run history
    # ------------------------------------------------------------------

    def save_run(
        self,
        duration_s: float,
        articles_fetched: int,
        articles_new: int,
        articles_deduped: int,
        mode: str = "fusion",
    ) -> None:
        """Enregistre les métriques d'un run complet.

        Args:
            duration_s: Durée du run en secondes.
            articles_fetched: Articles collectés.
            articles_new: Nouveaux articles (non doublons).
            articles_deduped: Articles filtrés comme doublons.
            mode: Mode de collecte (cyber, strat, leak, fusion).
        """
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO run_history
                (run_at, duration_s, articles_fetched, articles_new, articles_deduped, mode)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                duration_s,
                articles_fetched,
                articles_new,
                articles_deduped,
                mode,
            ),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    def prune_old_articles(self) -> int:
        """Supprime les articles plus anciens que retention_days.

        Returns:
            Nombre d'articles supprimés.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        ).isoformat()
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM articles WHERE published < ?", (cutoff,)
        )
        conn.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"Pruning : {count} articles supprimés (>{self.retention_days}j)")
        return count

    # ------------------------------------------------------------------
    # Utils
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """Convertit une Row SQLite en dict avec désérialisation JSON.

        Args:
            row: Row SQLite.

        Returns:
            Dictionnaire Python.
        """
        d = dict(row)
        for key in ("theatres", "actors", "cves", "tags", "risk_breakdown", "strat_breakdown"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    d[key] = []
        return d
