"""
exporters/report_generator.py — Générateur de rapports Jinja2 pour FULCRUM

Produit les rapports textuels et HTML via templates Jinja2 personnalisables :
  - daily_brief.j2    : brief quotidien opérationnel
  - weekly_strategic.j2 : synthèse stratégique hebdomadaire
  - incident_flash.j2   : alerte flash d'incident majeur

Fallback texte brut si Jinja2 n'est pas disponible.

Google-style docstrings.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("FULCRUM.reports")

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    logger.warning("Jinja2 non disponible — rapports en texte brut activés")


def _build_jinja_env() -> Optional[Any]:
    """Construit l'environnement Jinja2 avec le répertoire de templates.

    Returns:
        Environment Jinja2 ou None si non disponible.
    """
    if not JINJA2_AVAILABLE:
        return None
    if not _TEMPLATES_DIR.exists():
        logger.warning(f"Répertoire templates introuvable : {_TEMPLATES_DIR}")
        return None
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


_JINJA_ENV = _build_jinja_env()


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Génère des rapports structurés depuis les takeaways FULCRUM.

    Args:
        templates_dir: Répertoire de templates Jinja2 (override optionnel).

    Example:
        >>> from analyzers.takeaway_generator import TakeawayGenerator
        >>> gen = TakeawayGenerator(articles, stats)
        >>> brief_data = gen.daily_brief()
        >>> reporter = ReportGenerator()
        >>> text = reporter.render("daily_brief", brief_data)
        >>> reporter.save(text, "reports/brief_2026-03-23.txt")
    """

    def __init__(self, templates_dir: Optional[Path] = None) -> None:
        global _JINJA_ENV
        if templates_dir and JINJA2_AVAILABLE:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            _JINJA_ENV = Environment(
                loader=FileSystemLoader(str(templates_dir)),
                autoescape=select_autoescape(["html"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        self._env = _JINJA_ENV

    def render(self, report_type: str, data: Dict[str, Any]) -> str:
        """Rend un rapport à partir d'un template Jinja2.

        Args:
            report_type: Nom du template sans extension
                         (daily_brief | weekly_strategic | incident_flash).
            data: Données issues de TakeawayGenerator.

        Returns:
            Rapport rendu en texte brut.
        """
        template_name = f"{report_type}.j2"

        if self._env:
            try:
                tmpl = self._env.get_template(template_name)
                return tmpl.render(**data)
            except Exception as exc:
                logger.error(f"Erreur rendu template {template_name}: {exc}")

        # Fallback texte brut
        return self._render_fallback(report_type, data)

    def save(self, content: str, output_path: str) -> Path:
        """Sauvegarde un rapport rendu dans un fichier.

        Args:
            content: Contenu textuel du rapport.
            output_path: Chemin de sortie.

        Returns:
            Chemin du fichier créé.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"Rapport sauvegardé : {path}")
        return path

    def render_and_save(
        self, report_type: str, data: Dict[str, Any], output_path: str
    ) -> Path:
        """Rend et sauvegarde un rapport en une seule opération.

        Args:
            report_type: Type de rapport.
            data: Données du takeaway.
            output_path: Chemin de sortie.

        Returns:
            Chemin du fichier généré.
        """
        content = self.render(report_type, data)
        return self.save(content, output_path)

    # ------------------------------------------------------------------
    # Fallback texte brut
    # ------------------------------------------------------------------

    @staticmethod
    def _render_fallback(report_type: str, data: Dict[str, Any]) -> str:
        """Rendu minimaliste en texte brut sans Jinja2.

        Args:
            report_type: Type de rapport.
            data: Données du takeaway.

        Returns:
            Texte structuré.
        """
        lines = [
            "=" * 80,
            f"  FULCRUM {report_type.upper().replace('_', ' ')}",
            f"  {data.get('generated_at', '')[:16]} UTC  |  {data.get('period', '')}",
            "=" * 80,
            "",
            data.get("headline", ""),
            "",
        ]

        for section in data.get("sections", []):
            lines.append("-" * 40)
            lines.append(f"  {section.get('title', '')}")
            lines.append("-" * 40)
            for item in section.get("items", []):
                lines.append(f"  • {item}")
            lines.append("")

        # Pour incident_flash
        if "incident" in data:
            inc = data["incident"]
            lines.extend([
                f"  TYPE     : {inc.get('type', '')}",
                f"  SÉVÉRITÉ : {inc.get('severity', '')}",
                f"  SCORE    : {inc.get('composite_score', 0)}/100",
                f"  TITRE    : {inc.get('title', '')[:75]}",
                "",
                "  ACTIONS RECOMMANDÉES",
            ])
            for i, action in enumerate(data.get("recommended_actions", []), 1):
                lines.append(f"  [{i}] {action}")

        lines.append("=" * 80)
        return "\n".join(lines)
