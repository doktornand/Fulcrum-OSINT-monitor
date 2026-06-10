"""
exporters/json_exporter.py — Export JSON structuré pour FULCRUM

Génère un export JSON avec :
  - Schéma validé et métadonnées enrichies
  - Décomposition des scores (risk_breakdown, strat_breakdown)
  - Statistiques globales et par théâtre
  - Résumé des IOCs et clusters

Google-style docstrings.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("FULCRUM.export.json")

# Schéma version pour compatibilité future
_SCHEMA_VERSION = "3.1"


class JSONExporter:
    """Exporte les articles FULCRUM en JSON structuré et validé.

    Args:
        output_path: Chemin du fichier JSON de sortie.
        indent: Indentation JSON (défaut 2).
        include_raw_content: Si True, inclut le contenu brut des articles.

    Example:
        >>> exporter = JSONExporter("fulcrum_export.json")
        >>> exporter.export(articles, stats)
    """

    def __init__(
        self,
        output_path: str = "fulcrum_export.json",
        indent: int = 2,
        include_raw_content: bool = False,
    ) -> None:
        self.output_path = Path(output_path)
        self.indent = indent
        self.include_raw_content = include_raw_content

    def export(
        self,
        articles: List[Dict[str, Any]],
        stats: Optional[Dict[str, Any]] = None,
        clusters: Optional[Dict[str, list]] = None,
        run_metadata: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Génère le fichier JSON d'export.

        Args:
            articles: Liste de dicts articles FULCRUM.
            stats: Statistiques globales optionnelles.
            clusters: Clusters d'incidents détectés.
            run_metadata: Métadonnées du run (durée, mode…).

        Returns:
            Chemin du fichier généré.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Construction du document
        document = {
            "schema_version": _SCHEMA_VERSION,
            "generated_at": now,
            "metadata": {
                "total_articles": len(articles),
                "run": run_metadata or {},
            },
            "statistics": stats or {},
            "clusters": self._serialize_clusters(clusters or {}),
            "articles": [self._serialize_article(art) for art in articles],
        }

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(document, f, ensure_ascii=False, indent=self.indent, default=str)

        logger.info(f"Export JSON : {self.output_path} ({len(articles)} articles)")
        return self.output_path

    def _serialize_article(self, art: Dict[str, Any]) -> Dict[str, Any]:
        """Sérialise un article en dict JSON propre.

        Args:
            art: Dict de l'article.

        Returns:
            Dict sérialisable.
        """
        out = {
            "id": art.get("id", ""),
            "title": art.get("title", ""),
            "source": art.get("source", ""),
            "category": art.get("category", ""),
            "published": art.get("published", ""),
            "link": art.get("link", ""),
            "severity": art.get("severity", "INFO"),
            "risk_score": art.get("risk_score", 0),
            "strat_score": art.get("strat_score", 0),
            "risk_breakdown": art.get("risk_breakdown", {}),
            "strat_breakdown": art.get("strat_breakdown", {}),
            "cves": art.get("cves", []),
            "actors": art.get("actors", []),
            "theatres": art.get("theatres", []),
            "iocs": art.get("iocs", {}),
            "tags": art.get("tags", []),
            "confidence": art.get("confidence", 5),
        }

        if self.include_raw_content:
            out["summary"] = art.get("summary", "")

        return out

    @staticmethod
    def _serialize_clusters(clusters: Dict[str, list]) -> List[Dict[str, Any]]:
        """Sérialise les clusters pour l'export.

        Args:
            clusters: Dict cluster_id → liste d'articles.

        Returns:
            Liste de dicts cluster.
        """
        result = []
        for cluster_id, arts in clusters.items():
            result.append({
                "cluster_id": cluster_id,
                "article_count": len(arts),
                "article_ids": [art.get("id", "") for art in arts],
            })
        return result
